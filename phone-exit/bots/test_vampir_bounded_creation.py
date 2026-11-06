"""Real immutable profile with local runner/journal fixtures, no network login."""
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.bounded_creation_admission import scope, current, SOURCE
from vampir_core.character_create import CharacterCreatePayload, encode_character_create
from vampir_core.runtime_admission import permits as world_permits


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Vault:
    def encrypt(self, value): return value.encode()
    def decrypt(self, value): return bytes(value).decode()


class BoundedCreationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = load('bounded_creation_builder_test', HERE / 'resource-tools/vampir/build-bounded-creation-current.py')
        cls.profile = cls.builder.publish()
        cls.runner = load('bounded_creation_runner_test', HERE / 'vampir-headless/run-bounded-create.py')

    def test_profile_and_payload_do_not_admit_world(self):
        with scope(self.profile['selected_profile'], root=self.builder.ROOT, workspace=self.builder.WORKSPACE):
            profile = current()
            template = profile['payload_template']
            payload = CharacterCreatePayload(template['raw_class'], 'ExplicitName', tuple(template['appearance']),
                template['appearance_text'], tuple(template['raw_flags']), tuple(template['items']))
            encoded = encode_character_create(payload, source_sha256=SOURCE)
            self.assertEqual(int.from_bytes(encoded[:4], 'little'), 1)
            self.assertFalse(world_permits(SOURCE, 'game-login-world-v1'))
            self.assertFalse(profile['world_admitted'])
            self.assertFalse(profile['online_verified'])
            parent = load('bounded_creation_parent_test', HERE / 'vampir-headless/bounded-entry-profile.py')
            readonly = parent.load_manifest(profile['entry']['sha256'])
            self.assertFalse(readonly['creation_admitted'])
        with self.assertRaises(ValueError):
            encode_character_create(payload, source_sha256=SOURCE)

    def test_real_entrypoint_requires_create_capability_before_authentication(self):
        entry = load('current_create_real_entrypoint', HERE / 'vampir-headless/probe-selected-game-login.py')
        profile = json.loads(Path(self.profile['report']).read_bytes())
        args = dict(selected_profile=profile['entry']['selected_profile'], manifest_path=Path('unused.json'),
            socks_port=None, server_policy_byte=0, extra_number=268356, context='windows-sdk-initial-reset',
            region='EU', server_id=387, auth_flow='launcher', read_character_list=True,
            creation_factory=lambda characters: None)
        marker = dict(stage='reached_source_validation')
        with patch.object(entry, '_run', return_value=marker) as run:
            with self.assertRaisesRegex(ValueError, 'admitted profile'):
                entry.run('fixture@unit.invalid', **args)
            run.assert_not_called()
            with scope(self.profile['selected_profile'], root=self.builder.ROOT, workspace=self.builder.WORKSPACE):
                self.assertEqual(entry.run('fixture@unit.invalid', **args), marker)
            run.assert_called_once()

    def test_runner_records_once_then_assigns_only_fresh_server_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'accounts.sqlite3', Vault())
            account = store.save('fixture@unit.invalid', password='fixture', assignment=dict(region='EU',
                server_id=387, create_class='DarkMage', create_random_nickname=True))
            calls, proposed = [], []
            def entry(identifier, selector, *, progress, _creation_factory=None):
                self.assertEqual(identifier, account)
                calls.append(_creation_factory is not None)
                if _creation_factory is not None:
                    payload = _creation_factory(SimpleNamespace(result_code=0, records=()))
                    proposed.append(payload.name)
                    self.assertEqual(store.creation_attempts()[-1]['state'], 'pending')
                    return dict(result=dict(game=dict(character_creation_state='created',
                        character_creation_result_code=0, created_character_key='987654',
                        created_character_name='ServerIdentity')))
                self.assertEqual(store.creation_attempts()[-1]['state'], 'created')
                row = dict(index=0, key='987654', name='ServerIdentity')
                store.save_characters(account, region='EU', server_id=387, characters=[row],
                    observed_utc=datetime.now(timezone.utc).isoformat())
                return dict(result=dict(game=dict(character_list_received=True,
                    character_list_result_code=0, characters=[row])))
            with patch.object(self.runner, 'AccountStore', return_value=store), \
                    patch.object(self.runner, 'load_entry', return_value=SimpleNamespace(run=entry)):
                result = self.runner.run(account, self.profile['selected_profile'])
            self.assertEqual(calls, [True, False])
            self.assertTrue(proposed[0])
            assignment = store.accounts()[0]
            self.assertEqual((assignment['character_index'], assignment['character_key']), (0, '987654'))
            self.assertEqual(store.creation_attempts()[0]['state'], 'existing_verified')
            self.assertEqual(store.creation_attempts()[0]['character_name'], 'ServerIdentity')
            self.assertTrue(result['attempt_recorded'])
            self.assertFalse(result['world_entered'])

    def test_failed_login_preserves_pending_as_unknown_and_never_repeats(self):
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'accounts.sqlite3', Vault())
            account = store.save('fixture@unit.invalid', password='fixture', assignment=dict(region='EU',
                server_id=387, create_class='DarkMage', create_random_nickname=True))
            def entry(identifier, selector, *, progress, _creation_factory=None):
                _creation_factory(SimpleNamespace(result_code=0, records=()))
                raise OSError('Synthetic transport loss after preparation')
            with patch.object(self.runner, 'AccountStore', return_value=store), \
                    patch.object(self.runner, 'load_entry', return_value=SimpleNamespace(run=entry)):
                with self.assertRaises(OSError):
                    self.runner.run(account, self.profile['selected_profile'])
                self.assertEqual(store.creation_attempts()[0]['state'], 'unknown')
                with self.assertRaisesRegex(RuntimeError, 'separately'):
                    self.runner.run(account, self.profile['selected_profile'])
            self.assertEqual(len(store.creation_attempts()), 1)


if __name__ == '__main__':
    unittest.main()
