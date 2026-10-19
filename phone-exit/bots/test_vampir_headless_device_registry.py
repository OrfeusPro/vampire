"""Persistence and isolation of local device bindings, no game access."""
from pathlib import Path
from contextlib import closing
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.device_registry import DeviceRegistry


class DeviceRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'accounts.sqlite3'
        self.registry = DeviceRegistry(self.path)

    def test_restart_and_idempotent_registration(self):
        first = self.registry.register('Main@example.invalid', kind='real', is_main=True)
        second = DeviceRegistry(self.path).register('main@example.invalid', kind='real', is_main=True)
        self.assertEqual(first, second)
        self.assertFalse(first.identity_recorded)
        self.assertEqual(first.confirmation, 'unknown')
        self.assertNotIn('example.invalid', repr(first))
        with self.assertRaises(ValueError):
            self.registry.register(first.email, kind='planned')
        with self.assertRaises(sqlite3.IntegrityError):
            self.registry.register('other@example.invalid', kind='real', is_main=True)

    def test_identity_is_stable_and_confirmation_is_independent(self):
        self.registry.register('main@example.invalid', kind='real')
        args = dict(device_key='observed-device', nm_device_key='observed-nm', source='synthetic test fixture')
        self.registry.record_real_identity('main@example.invalid', **args)
        self.registry.record_real_identity('main@example.invalid', **args)
        with self.assertRaises(ValueError):
            self.registry.record_real_identity('main@example.invalid', **dict(args, device_key='replacement'))
        self.registry.record_confirmation('main@example.invalid', evidence='Synthetic manual confirmation fixture')
        bound = self.registry.require_confirmation('main@example.invalid')
        self.assertEqual(bound.confirmation, 'required')
        self.assertEqual(bound.confirmation_evidence, '')
        restored = DeviceRegistry(self.path).get(bound.email)
        self.assertTrue(restored.identity_recorded)
        self.assertEqual(restored.device_key, args['device_key'])
        self.assertEqual(restored.confirmation, 'required')

    def test_accounts_are_isolated_and_planned_is_not_real(self):
        a = self.registry.register('one@example.invalid', kind='real')
        b = self.registry.register('two@example.invalid')
        self.assertNotEqual(a.profile_id, b.profile_id)
        self.registry.require_confirmation(a.email)
        self.assertEqual(self.registry.get(b.email).confirmation, 'unknown')
        with self.assertRaises(ValueError):
            self.registry.record_confirmation(a.email, evidence='fixture')
        with self.assertRaises(ValueError):
            self.registry.record_real_identity(b.email, device_key='x', nm_device_key='y', source='fixture')
        with self.assertRaises(KeyError):
            self.registry.require_confirmation('missing@example.invalid')

    def test_nid_identity_is_separate_stable_and_invalidates_old_confirmation(self):
        a = self.registry.register('main@example.invalid', kind='real')
        self.registry.record_real_identity(a.email, device_key='sdk-fixture', nm_device_key='nm-fixture', source='fixture')
        self.registry.record_confirmation(a.email, evidence='Old fixture confirmation')
        b = self.registry.record_real_nid_identity(a.email, nid_device_key='nid-fixture', source='nid-observation-fixture')
        self.assertEqual(b.device_key, 'sdk-fixture')
        self.assertEqual(b.nm_device_key, 'nm-fixture')
        self.assertTrue(b.nid_identity_recorded)
        self.assertEqual(b.confirmation, 'unknown')
        self.assertNotIn('nid-fixture', repr(b))
        self.registry.record_confirmation(a.email, evidence='New fixture confirmation')
        self.registry.record_real_nid_identity(a.email, nid_device_key='nid-fixture', source='nid-observation-fixture')
        restored = DeviceRegistry(self.path).get(a.email)
        self.assertEqual(restored.confirmation, 'confirmed')
        self.assertEqual(restored.profile_id, a.profile_id)
        with self.assertRaises(ValueError):
            self.registry.record_real_nid_identity(a.email, nid_device_key='replacement', source='fixture')
        other = self.registry.register('planned@example.invalid')
        with self.assertRaises(ValueError):
            self.registry.record_real_nid_identity(other.email, nid_device_key='nid-fixture', source='fixture')

    def test_v1_migration_preserves_profile_and_never_invents_nid_identity(self):
        legacy = Path(self.temp.name) / 'legacy.sqlite3'
        with closing(sqlite3.connect(legacy)) as db, db:
            db.execute('''CREATE TABLE bindings (
                email TEXT PRIMARY KEY COLLATE NOCASE, profile_id TEXT UNIQUE, kind TEXT,
                is_main INTEGER, device_key TEXT, nm_device_key TEXT, identity_source TEXT,
                confirmation TEXT, confirmation_evidence TEXT, updated_at TEXT)''')
            db.execute('INSERT INTO bindings VALUES(?,?,?,?,?,?,?,?,?,?)',
                       ('legacy@example.invalid','stable-fixture','real',1,'sdk','nm','fixture','required','','2026-10-19'))
            db.execute('PRAGMA user_version=1')
        registry = DeviceRegistry(legacy)
        bound = registry.get('legacy@example.invalid')
        self.assertEqual(bound.profile_id, 'stable-fixture')
        self.assertEqual(bound.device_key, 'sdk')
        self.assertEqual(bound.confirmation, 'required')
        self.assertEqual(bound.nid_device_key, '')
        self.assertFalse(bound.nid_identity_recorded)
        self.assertEqual(DeviceRegistry(legacy).get(bound.email), bound)
        with closing(sqlite3.connect(legacy)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)


if __name__ == '__main__':
    unittest.main()
