"""Creation capability isolation and durable unknown outcome, without auth/IO."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core import bounded_creation_admission as admission
from vampir_core.account_store import AccountStore
from vampir_core.character_appearance import encode_character_appearance
from vampir_core.character_create import CharacterCreatePayload, encode_character_create
from vampir_core.character_create_result import CharacterCreateResult, character_creation_outcome
from vampir_core.character_creation_flow import CharacterCreationFlow
from vampir_core.character_list import CharacterRecord
from vampir_core.runtime_admission import permits as world_permits
from vampir_core.selection_flow import SelectionState

SELECTOR = 'bounded-create:' + '1' * 64
ENTRY = 'bounded-entry:' + '2' * 64


def load_profile_tool():
    path = HERE / 'vampir-headless/bounded-creation-profile.py'
    spec = importlib.util.spec_from_file_location('creation_profile_test_loader', path)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


@contextmanager
def admitted():
    # These explicit admission fixtures isolate worker-context behavior. The
    # real stdlib manifest loader has separate hash/scope tests below.
    profile = dict(source_sha256=admission.SOURCE, policy=admission.POLICY,
        selected_profile=SELECTOR, entry=dict(selected_profile=ENTRY))
    @contextmanager
    def entry_scope(selector, **kwargs):
        if selector != ENTRY:
            raise ValueError('Different entry')
        yield selector
    with patch.object(admission, '_load', return_value=profile), \
         patch('vampir_core.bounded_entry_admission.scope', entry_scope), \
         admission.scope(SELECTOR, root=Path('.'), workspace=Path('.')):
        yield


class Vault:
    def encrypt(self, value): return value.encode()
    def decrypt(self, value): return bytes(value).decode()


class CreationAdmissionTests(unittest.TestCase):
    def payload(self):
        text = encode_character_appearance(dict(Height=0.5, Chest=0.5, Pelvis=0.5,
            Shape=0.5, Waist=0.5, Thigh=0.5, Head=0.5), 1,
            source_sha256=admission.SOURCE, key_profile='latin')
        return CharacterCreatePayload(1, 'ProposedHero', (1, 1, 0, 1, 2, 1, 1, 0, 0, 1), text, (0, 0), ())

    def test_context_is_exact_nested_and_worker_local(self):
        self.assertFalse(admission.permits(admission.SOURCE))
        with admitted():
            self.assertTrue(admission.permits(admission.SOURCE))
            self.assertFalse(admission.permits('0' * 64))
            self.assertFalse(admission.permits(admission.SOURCE, 'game-login-world-v1'))
            self.assertFalse(world_permits(admission.SOURCE, 'game-login-world-v1'))
            snapshot = admission.current(SELECTOR)
            snapshot['policy'] = 'forged'
            self.assertEqual(admission.current()['policy'], admission.POLICY)
            with admission.scope(SELECTOR, root=Path('.'), workspace=Path('.')):
                self.assertTrue(admission.permits(admission.SOURCE))
            with self.assertRaisesRegex(ValueError, 'switch'):
                with admission.scope('bounded-create:' + '3' * 64, root=Path('.'), workspace=Path('.')):
                    pass
            seen = []
            thread = threading.Thread(target=lambda: seen.append(admission.permits(admission.SOURCE)))
            thread.start(); thread.join(2)
            self.assertEqual(seen, [False])
        self.assertFalse(admission.permits(admission.SOURCE))
        with self.assertRaisesRegex(ValueError, 'active verified'):
            admission.current()

    def test_current_codecs_and_single_attempt_keep_server_identity(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported'):
            self.payload()
        with admitted():
            payload = self.payload()
            raw = encode_character_create(payload, source_sha256=admission.SOURCE)
            self.assertEqual(int.from_bytes(raw[:4], 'little'), 1)
            queued = []
            outbound = SimpleNamespace(queue_character_create=lambda value, **kwargs: queued.append(value) or value)
            flow = CharacterCreationFlow(outbound, source_sha256=admission.SOURCE, timeout=2)
            selection = SimpleNamespace(state=SelectionState.LIST_AVAILABLE, result_code=0,
                characters=SimpleNamespace(result_code=0, records=()))
            flow.queue(payload, selection, now=0)
            self.assertEqual(len(queued), 1)
            flow.frame_sent(payload)
            self.assertTrue(flow.expire(now=2))
            self.assertEqual(flow.state, 'unknown')
            with self.assertRaisesRegex(RuntimeError, 'already consumed'):
                flow.queue(payload, selection, now=2)
            record = CharacterRecord(('ServerName',), (), (), (123,), 0, (), (), (), None, False)
            outcome = character_creation_outcome(CharacterCreateResult(0, record),
                source_sha256=admission.SOURCE, requested_name=payload.name)
            self.assertEqual((outcome.status, outcome.character_key, outcome.character_name), ('created', 123, 'ServerName'))
            self.assertFalse(outcome.requested_name_matches)
            rejected = character_creation_outcome(CharacterCreateResult(58, record),
                source_sha256=admission.SOURCE, requested_name=payload.name)
            self.assertEqual(rejected.status, 'rejected')
            self.assertIsNone(rejected.character_key)
            self.assertFalse(rejected.retry_allowed)
        with self.assertRaisesRegex(ValueError, 'Unsupported'):
            encode_character_create(payload, source_sha256=admission.SOURCE)

    def test_journal_keeps_unknown_across_scope_and_requires_fresh_list(self):
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'accounts.sqlite3', Vault())
            identifier = store.save('fixture@unit.invalid', password='fixture', assignment=dict(
                region='EU', server_id=387, create_class='DarkMage', create_nickname='ProposedHero'))
            def listing(fresh=False):
                delta = timedelta(seconds=1 if fresh else -1)
                store.save_characters(identifier, region='EU', server_id=387, characters=[],
                    observed_utc=(datetime.now(timezone.utc) + delta).isoformat())
            def begin():
                return store.begin_creation(identifier, region='EU', server_id=387,
                    nickname='ProposedHero', source_sha256=admission.SOURCE)
            listing()
            with self.assertRaises(ValueError): begin()
            with admitted():
                token = begin()
                store.finish_creation(token, state='unknown')
                with self.assertRaises(RuntimeError): begin()
            reopened = AccountStore(store.path, Vault())
            self.assertEqual(reopened.creation_attempts()[0]['state'], 'unknown')
            with self.assertRaises(ValueError):
                reopened.reconcile_creation(identifier, region='EU', server_id=387)
            listing(True)
            self.assertEqual(reopened.reconcile_creation(identifier, region='EU', server_id=387), 'empty_verified')
            with admitted():
                self.assertNotEqual(begin(), token)

    def test_stdlib_loader_rejects_scope_hash_and_bad_numeric_template(self):
        tool = load_profile_tool()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            profile = dict(schema=1, recipe=tool.RECIPE, source_sha256=tool.SOURCE,
                operations=['world'], policy=tool.POLICY, world_admitted=False,
                online_verified=False, creation_admitted=True, limits=['fixture'])
            raw = json.dumps(profile).encode()
            import hashlib
            sha = hashlib.sha256(raw).hexdigest()
            path = root / 'bounded-creation-profiles' / sha / 'manifest.json'
            path.parent.mkdir(parents=True); path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'scope differs'):
                tool.load_manifest(sha, root=root)
            path.write_bytes(raw + b' ')
            with self.assertRaisesRegex(ValueError, 'manifest changed'):
                tool.load_manifest(sha, root=root)
        template = dict(raw_class=1, appearance=[1] * 10, appearance_text=json.dumps(
            {str(n): 0.5 for n in range(1, 8)} | {'VoiceType': 1}), raw_flags=[0, 0], items=[])
        tool._payload(template)
        for key, value in (('raw_class', 3), ('appearance', [0] * 10),
                           ('appearance_text', '{"1":NaN}')):
            with self.assertRaises(ValueError):
                tool._payload(dict(template, **{key: value}))


if __name__ == '__main__':
    unittest.main()
