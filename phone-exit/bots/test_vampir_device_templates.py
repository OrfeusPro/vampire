"""Local device-template allocation; fixtures only, without auth or live data."""
from copy import deepcopy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest


HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.bot_device_settings import new_identity


class FixtureVault:
    def encrypt(self, text):
        return b'fixture-only:' + text.encode('utf-8')[::-1]

    def decrypt(self, data):
        if not data.startswith(b'fixture-only:'):
            raise AssertionError('Only fixture credentials may be decrypted')
        return data[len(b'fixture-only:'):][::-1].decode('utf-8')


def baseline():
    return dict(cpu=dict(vendor='AuthenticAMD', brand='Fixture CPU'),
        windows=dict(major=10, minor=0, build=26200, product_type=1, suite_mask=256),
        metadata=dict(I_DeviceModel='Fixture Desktop', I_NMRAM='32 GiB', I_NMVGA='Fixture GPU'))


def template_settings():
    return dict(baseline(), identity=new_identity())


class DeviceTemplateTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / 'console.sqlite3'
        self.store = AccountStore(self.path, FixtureVault())

    def account(self, number, **assignment):
        return self.store.save(f'fixture{number}@unit.invalid', password=f'game-fixture-{number}',
            mail_password=f'mail-fixture-{number}', assignment=assignment)

    def current(self, identifier):
        return next(a for a in self.store.accounts() if a['id'] == identifier)

    def save_current(self, identifier, **changes):
        account = self.current(identifier)
        settings = {key: account[key] for key in AccountStore.assignment({})}
        settings.update(changes)
        return self.store.save(account['email'], assignment=settings)

    def new_template(self, name='Fixture PC', device_name='FIXTURE-PC'):
        return self.store.save_device_template(name=name, device_name=device_name, settings=template_settings())

    def raw_accounts(self):
        with closing(sqlite3.connect(self.path)) as db:
            return {row[0]: row for row in db.execute('SELECT id,email,password,mail_password,assignment FROM accounts')}

    def test_device_types_are_explicit_and_do_not_change_hardware_identity(self):
        identifier = self.account(1)
        template = self.new_template()
        self.store.assign_device_template(identifier, template)
        fingerprint = self.store._fingerprint(self.current(identifier))
        for kind in ('Телефон', 'ПК', 'UgPhone', 'LdCloud', 'Бот', 'Не задействован', 'Не использовать'):
            self.save_current(identifier, device_type=kind)
            self.assertEqual(self.current(identifier)['device_type'], kind)
            self.assertEqual(self.store._fingerprint(self.current(identifier)), fingerprint)
        with self.assertRaises(ValueError):
            self.save_current(identifier, device_type='Unknown')

    def test_excluded_and_reserve_modes_keep_reserved_device_slots_and_explicit_enablement(self):
        first, second, third = [self.account(i) for i in range(3)]
        template = self.new_template()
        self.store.assign_device_template(first, template)
        self.store.assign_device_template(second, template)
        self.save_current(first, device_type='Не использовать', enabled=True)
        excluded = self.current(first)
        self.assertFalse(excluded['enabled'])
        self.assertEqual(excluded['device_type'], 'Не использовать')
        self.assertEqual(excluded['device_template_id'], template)
        with self.assertRaises(ValueError):
            self.store.assign_device_template(third, template)
        reopened = AccountStore(self.path, FixtureVault())
        self.assertFalse(next(a for a in reopened.accounts() if a['id'] == first)['enabled'])
        self.save_current(first, device_type='Не задействован', enabled=True)
        reserve = self.current(first)
        self.assertTrue(reserve['enabled'])
        self.assertEqual(reserve['device_template_id'], template)
        self.assertEqual(len(self.store.device_templates()[0]['members']), 2)

    def test_generation_allocates_29_accounts_to_15_persistent_devices_without_replacing_credentials(self):
        identifiers = [self.account(i, label=f'Fixture {i}', server_id=381 + i % 2, socks_port=1081 if i % 3 == 0 else None)
                       for i in range(29)]
        active = [dict(email=f'fixture{i}@unit.invalid', region='EU', server_id=381 + i % 2,
                       character_name=f'Player{i}', device='UgPhone') for i in range(17)]
        self.store.update_active_game_roster(active)
        self.store.save_verification_checkpoint(dict(state='completed', completed=identifiers[:3]))
        before = self.raw_accounts()
        original_baseline = baseline()
        generated = self.store.generate_device_templates(original_baseline)
        self.assertEqual(generated, dict(created=15, assigned=29, templates=15))
        self.assertEqual(original_baseline, baseline())
        templates = self.store.device_templates()
        self.assertEqual(sorted(len(t['members']) for t in templates), [1] + [2] * 14)
        keys = [key for t in templates for key in t['settings']['identity'].values()]
        self.assertEqual(len(set(keys)), 45)
        for template in templates:
            self.assertEqual(template['capacity'], 2)
            self.assertEqual(template['settings']['cpu'], original_baseline['cpu'])
            self.assertEqual(template['settings']['metadata'], original_baseline['metadata'])
            self.assertTrue(template['device_name'])
            self.assertRegex(template['device_name'], r'^DESKTOP-[A-Z0-9]{7}$')
        self.assertEqual(len({t['device_name'] for t in templates}), 15)
        after = self.raw_accounts()
        for identifier, row in before.items():
            self.assertEqual(after[identifier][:4], row[:4])
            original = json.loads(row[4])
            updated = json.loads(after[identifier][4])
            updated.pop('device_template_id')
            original.pop('device_template_id')
            self.assertEqual(updated, original)
        restarted = AccountStore(self.path, FixtureVault())
        self.assertEqual(restarted.device_templates(), templates)
        self.assertEqual(restarted.generate_device_templates(baseline()), dict(created=0, assigned=0, templates=15))
        self.assertEqual(restarted.device_templates(), templates)
        self.assertEqual(restarted.load_verification_checkpoint(), dict(state='completed', completed=identifiers[:3]))
        self.assertEqual(len([a for a in restarted.accounts() if a['reported_device'] == 'UgPhone']), 17)

    def test_assignment_and_save_both_reject_a_third_slot_and_roll_back(self):
        first, second, third = [self.account(i) for i in range(3)]
        template = self.new_template()
        self.store.assign_device_template(first, template)
        self.save_current(second, device_template_id=template)
        before = self.raw_accounts()
        with self.assertRaisesRegex(ValueError, '2'):
            self.store.assign_device_template(third, template)
        with self.assertRaisesRegex(ValueError, '2'):
            self.save_current(third, device_template_id=template, label='Must roll back')
        with self.assertRaisesRegex(ValueError, '2'):
            self.store.save('new@unit.invalid', password='fixture', assignment={'device_template_id': template})
        self.assertEqual(self.raw_accounts(), before)
        self.store.assign_device_template(second, None)
        self.store.assign_device_template(third, template)
        members = self.store.device_templates()[0]['members']
        self.assertEqual({member['id'] for member in members}, {first, third})
        self.store.assign_device_template(first, template)
        self.assertEqual(len(self.store.device_templates()[0]['members']), 2)

    def test_competing_assignments_cannot_overbook_the_last_slot(self):
        first, second, third = [self.account(i) for i in range(3)]
        template = self.new_template()
        self.store.assign_device_template(first, template)
        stores = [AccountStore(self.path, FixtureVault()) for _ in range(2)]
        barrier = threading.Barrier(2)
        outcomes = []
        lock = threading.Lock()
        def assign(store, account):
            try:
                barrier.wait(timeout=3)
                store.assign_device_template(account, template)
                outcome = 'assigned'
            except ValueError:
                outcome = 'full'
            except Exception as error:
                outcome = type(error).__name__
            with lock:
                outcomes.append(outcome)
        workers = [threading.Thread(target=assign, args=pair) for pair in zip(stores, (second, third))]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=7)
            self.assertFalse(worker.is_alive())
        self.assertCountEqual(outcomes, ['assigned', 'full'])
        self.assertEqual(len(self.store.device_templates()[0]['members']), 2)

    def test_effective_worker_credentials_share_the_template_but_keep_individual_routes_and_legacy_fallbacks(self):
        legacy = dict(identity=new_identity(), metadata={'I_DeviceModel': 'Legacy fixture'})
        first = self.account(1, device_profile='custom', device_settings=legacy, device_name='OLD-PC', socks_port=1081)
        second = self.account(2, socks_port=None)
        template = self.new_template()
        self.store.assign_device_template(first, template)
        self.store.assign_device_template(second, template)
        email, password, effective = self.store.credential(first)
        self.assertEqual((email, password), ('fixture1@unit.invalid', 'game-fixture-1'))
        first_row, second_row = self.current(first), self.current(second)
        self.assertEqual(effective['device_settings'], first_row['device_settings'])
        self.assertEqual(first_row['device_settings'], second_row['device_settings'])
        self.assertEqual(first_row['device_name'], 'FIXTURE-PC')
        self.assertEqual(first_row['device_profile'], 'custom')
        self.assertEqual(first_row['socks_port'], 1081)
        self.assertIsNone(second_row['socks_port'])
        first_row['device_settings']['metadata']['I_DeviceModel'] = 'Mutated return value'
        self.assertEqual(self.current(second)['device_settings']['metadata']['I_DeviceModel'], 'Fixture Desktop')
        self.save_current(first, label='Renamed account')
        self.store.assign_device_template(first, None)
        unassigned = self.current(first)
        self.assertEqual(unassigned['device_settings'], legacy)
        self.assertEqual(unassigned['device_name'], 'OLD-PC')
        self.assertEqual(unassigned['socks_port'], 1081)
        self.assertEqual(self.store.reveal_password(first, 'mail'), 'mail-fixture-1')

    def test_console_save_unassigns_without_copying_shared_keys_into_the_legacy_binding(self):
        legacy = dict(identity=new_identity(), metadata={'I_DeviceModel': 'Original fixture'})
        account = self.account(1, device_profile='custom', device_settings=legacy,
                               device_name='ORIGINAL-PC', socks_port=1081)
        template = self.new_template()
        self.store.assign_device_template(account, template)
        shared = self.current(account)['device_settings']
        self.assertNotEqual(shared['identity'], legacy['identity'])
        # /api/state and the console form contain the resolved template hardware.
        self.save_current(account, device_template_id=None, label='After unassignment', socks_port=None)
        restored = self.current(account)
        self.assertIsNone(restored['device_template_id'])
        self.assertEqual(restored['device_profile'], 'custom')
        self.assertEqual(restored['device_settings'], legacy)
        self.assertEqual(restored['device_name'], 'ORIGINAL-PC')
        self.assertEqual(restored['label'], 'After unassignment')
        self.assertIsNone(restored['socks_port'])
        self.assertEqual(self.store.device_templates()[0]['members'], [])
        self.assertEqual(self.store.reveal_password(account, 'netmarble'), 'game-fixture-1')
        restarted = AccountStore(self.path, FixtureVault())
        restored = next(a for a in restarted.accounts() if a['id'] == account)
        self.assertEqual(restored['device_settings'], legacy)
        self.assertEqual(restored['device_name'], 'ORIGINAL-PC')

    def test_google_membership_never_creates_a_netmarble_or_mail_password(self):
        google = self.store.save('google@unit.invalid', assignment={'login_provider': 'google'})
        template = self.new_template()
        self.store.assign_device_template(google, template)
        account = self.current(google)
        self.assertEqual(account['login_provider'], 'google')
        self.assertFalse(account['password_saved'])
        self.assertFalse(account['mail_password_saved'])
        self.assertEqual(account['device_name'], 'FIXTURE-PC')
        with self.assertRaises(ValueError):
            self.store.credential(google)
        with self.assertRaises(ValueError):
            self.store.reveal_password(google, 'netmarble')
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT length(password),mail_password FROM accounts WHERE id=?', (google,)).fetchone(), (0, None))

    def test_device_edit_invalidates_only_its_members_and_rejects_stale_verification(self):
        first, second, other = [self.account(i) for i in range(3)]
        template, separate = self.new_template(), self.new_template('Other PC', 'OTHER-PC')
        for account, device in ((first, template), (second, template), (other, separate)):
            self.store.assign_device_template(account, device)
            self.assertTrue(self.store.record_device_verification(account, self.store._fingerprint(self.current(account))))
        old = self.store._fingerprint(self.current(first))
        original = next(t for t in self.store.device_templates() if t['id'] == template)
        self.store.save_device_template(identifier=template, name='Friendly display name',
            device_name='RENAMED-PC', settings=original['settings'])
        self.assertFalse(self.current(first)['device_verified'])
        self.assertFalse(self.current(second)['device_verified'])
        self.assertTrue(self.current(other)['device_verified'])
        self.assertFalse(self.store.record_device_verification(first, old))
        self.assertEqual(self.current(first)['device_name'], 'RENAMED-PC')
        self.assertEqual(self.current(first)['device_template_name'], 'Friendly display name')
        self.assertTrue(self.store.record_device_verification(first, self.store._fingerprint(self.current(first))))
        changed = deepcopy(original['settings'])
        changed['metadata']['I_NMVGA'] = 'Changed fixture GPU'
        self.store.save_device_template(identifier=template, name='Friendly display name', device_name='RENAMED-PC', settings=changed)
        self.assertFalse(self.current(first)['device_verified'])
        self.assertEqual(self.current(other)['device_settings']['metadata']['I_NMVGA'], 'Fixture GPU')

    def test_display_name_edit_keeps_sdk_admission_but_identity_change_invalidates_members(self):
        first, second, other = [self.account(i) for i in range(3)]
        template = self.new_template()
        for account in (first, second):
            self.store.assign_device_template(account, template)
        for account in (first, second, other):
            self.store.registration_status(account, 'sdk_created')
            self.assertTrue(self.store.record_device_verification(account, self.store._fingerprint(self.current(account))))
        original = self.store.device_templates()[0]
        fingerprints = {account: self.store._fingerprint(self.current(account)) for account in (first, second)}
        for name in ('Display label only', 'Display label only'):
            self.store.save_device_template(identifier=template, name=name,
                device_name=original['device_name'], settings=original['settings'])
            for account in (first, second, other):
                self.assertEqual(self.current(account)['registration_status'], 'sdk_created')
                self.assertTrue(self.current(account)['device_verified'])
        changed = deepcopy(original['settings'])
        changed['identity'] = new_identity()
        self.store.save_device_template(identifier=template, name='Display label only',
            device_name=original['device_name'], settings=changed)
        for account in (first, second):
            self.assertEqual(self.current(account)['registration_status'], 'nid_verified')
            self.assertFalse(self.current(account)['device_verified'])
            self.assertFalse(self.store.record_device_verification(account, fingerprints[account]))
        self.assertEqual(self.current(other)['registration_status'], 'sdk_created')
        self.assertTrue(self.current(other)['device_verified'])

    def test_move_and_route_change_require_fresh_device_verification(self):
        account = self.account(1)
        first, second = self.new_template(), self.new_template('Second device', 'SECOND-PC')
        self.store.assign_device_template(account, first)
        old = self.store._fingerprint(self.current(account))
        self.assertTrue(self.store.record_device_verification(account, old))
        self.store.assign_device_template(account, second)
        self.assertFalse(self.current(account)['device_verified'])
        self.assertFalse(self.store.record_device_verification(account, old))
        self.assertEqual(len(next(t for t in self.store.device_templates() if t['id'] == first)['members']), 0)
        self.assertTrue(self.store.record_device_verification(account, self.store._fingerprint(self.current(account))))
        self.save_current(account, socks_port=1080)
        self.assertFalse(self.current(account)['device_verified'])

    def test_invalid_model_keys_and_duplicate_identity_leave_existing_devices_unchanged(self):
        first = self.new_template()
        original = self.store.device_templates()
        settings = deepcopy(original[0]['settings'])
        for invalid in ({k: v for k, v in settings.items() if k != 'identity'},
                        dict(settings, metadata={}),
                        dict(settings, identity={key: 'samekey' for key in settings['identity']})):
            with self.assertRaises(ValueError):
                self.store.save_device_template(name='Invalid PC', device_name='INVALID-PC', settings=invalid)
        with self.assertRaises(ValueError):
            self.store.save_device_template(name='Copied keys', device_name='COPIED-PC', settings=settings)
        with self.assertRaises(ValueError):
            self.store.save_device_template(name='Fixture PC', device_name='DUPLICATE', settings=template_settings())
        with self.assertRaises(ValueError):
            self.store.save_device_template(identifier='missing', name='Missing', device_name='MISSING', settings=template_settings())
        self.assertEqual(self.store.device_templates(), original)
        self.assertEqual(self.store.device_templates()[0]['id'], first)


if __name__ == '__main__':
    unittest.main()
