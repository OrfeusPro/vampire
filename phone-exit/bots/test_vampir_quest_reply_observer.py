"""Current reply observations require the retained proof and matching owner context."""
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core import bounded_world_admission
from vampir_core.live_session import LiveSession
from vampir_core.quest_record import CURRENT_SOURCE_SHA256
from vampir_core.quest_update_result import decode_quest_update_result, quest_reply_observation_permitted

SOURCE = bounded_world_admission.SOURCE
PROOF_SHA = 'a' * 64
PROOF_PATH = str(Path('F:/PhoneExit Resources/Vampir/code-clues/quest-reply-current-v1') / PROOF_SHA / 'manifest.json')
WIRE = struct.Struct('<IQBBQQ')


def profile():
    return dict(schema=2, source_sha256=SOURCE, world_admitted=True, policies=['quest-reply-observation-v1'],
                proofs={'quest-reply-current': dict(path=PROOF_PATH, sha256=PROOF_SHA)},
                inputs={PROOF_PATH: PROOF_SHA})


def owner(world=10010):
    position = SimpleNamespace(world_id=world, vector=SimpleNamespace(finite_values=lambda: (1., 2., 3.)))
    return SimpleNamespace(world_entry=SimpleNamespace(state='finish_response', target_position=position),
        selection=SimpleNamespace(response=SimpleNamespace(player=SimpleNamespace(at=lambda offset: 42)),
            characters=SimpleNamespace(records=[SimpleNamespace(u64=[42], strings=['Fixture'])])),
        heartbeat=SimpleNamespace(queued_count=1, response_count=1))


def body(code=0, key=110120, state=2, index=0):
    return WIRE.pack(code, key, state, index, 2**64-1, 2**63+1)


class QuestReplyObserverTests(unittest.TestCase):
    def session(self, bot='reply', source=SOURCE):
        session = LiveSession(bot_id=bot)
        session.bind_source(source)
        session.publish(owner())
        self.addCleanup(session.close)
        return session

    def receive(self, session, raw=None, **changes):
        context = dict(character_key=42, world_id=10010)
        context.update(changes)
        session.packet(1811, body() if raw is None else raw, **context)

    def test_current_decoder_requires_exact_scoped_reply_policy_and_retained_pointer(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported'):
            decode_quest_update_result(body(), source_sha256=SOURCE)
        with patch.object(bounded_world_admission, 'current', return_value=profile()):
            value = decode_quest_update_result(body(state=255, index=255), source_sha256=SOURCE)
            self.assertEqual((value.state, value.progress.raw08), (6, 255))
            self.assertEqual(value.progress.raw10, 2**64-1)
            self.assertFalse(quest_reply_observation_permitted('f' * 64))
        for mutation in ('source', 'policy', 'admission', 'missing_proof', 'pointer', 'retained'):
            value = profile()
            if mutation == 'source':
                value['source_sha256'] = 'f' * 64
            elif mutation == 'policy':
                value['policies'] = ['quest-observation-v1']
            elif mutation == 'admission':
                value['world_admitted'] = False
            elif mutation == 'missing_proof':
                value['proofs'] = {}
            elif mutation == 'pointer':
                value['proofs']['quest-reply-current']['path'] = PROOF_PATH.replace('code-clues', 'knowledge')
            else:
                value['inputs'] = {}
            with self.subTest(mutation=mutation), patch.object(bounded_world_admission, 'current', return_value=value):
                self.assertFalse(quest_reply_observation_permitted(SOURCE))
                with self.assertRaisesRegex(ValueError, 'Unsupported'):
                    decode_quest_update_result(body(), source_sha256=SOURCE)

    def test_legacy_decoder_remains_available_and_current_length_type_checks_hold(self):
        self.assertEqual(decode_quest_update_result(body(), source_sha256=CURRENT_SOURCE_SHA256).quest_id, 110120)
        with patch.object(bounded_world_admission, 'current', return_value=profile()):
            for raw in [body()[:length] for length in range(30)] + [body() + b'x', bytearray(body())]:
                with self.subTest(length=len(raw)), self.assertRaisesRegex(ValueError, 'complete 30-byte'):
                    decode_quest_update_result(raw, source_sha256=SOURCE)

    def test_session_publishes_current_reply_and_preserves_snapshot_isolation(self):
        with patch.object(bounded_world_admission, 'current', return_value=profile()):
            first, second = self.session('first'), self.session('second')
            self.assertEqual(first.snapshot()['coverage']['quest_result'], 'not_received')
            self.receive(first, body(code=0x1197, key=2**64-1, index=255))
            result = first.snapshot()['quest_update_result']
            self.assertEqual(result['quest_id'], str(2**64-1))
            self.assertEqual(result['progress']['raw10'], str(2**64-1))
            self.assertEqual(result['result_code'], 0x1197)
            self.assertFalse(result['action_confirmed'])
            self.assertFalse(result['applied_to_local_task'])
            self.assertEqual(result['correlation'], 'not_established')
            self.assertIsNone(second.snapshot()['quest_update_result'])
            result['progress']['raw08'] = 1
            self.assertEqual(first.snapshot()['quest_update_result']['progress']['raw08'], 255)

    def test_foreign_owner_world_bad_body_and_transition_are_fenced(self):
        with patch.object(bounded_world_admission, 'current', return_value=profile()):
            session = self.session()
            for context in ({'character_key': 43}, {'world_id': 10012}, {'character_key': True}, {'world_id': None}):
                self.receive(session, **context)
                self.assertIsNone(session.snapshot()['quest_update_result'])
            self.receive(session)
            self.receive(session, b'short')
            self.assertIsNone(session.snapshot()['quest_update_result'])
            self.assertEqual(session.snapshot()['quest_result_decode_errors'], 1)
            self.assertEqual(session.snapshot()['coverage']['quest_result'], 'decode_error')
            self.receive(session)
            session.publish(owner(10012))
            self.assertIsNone(session.snapshot()['quest_update_result'])
            self.assertEqual(session.snapshot()['coverage']['quest_result'], 'not_received')
            self.receive(session, world_id=10012)
            session.close()
            self.receive(session, world_id=10012)
            self.assertIsNone(session.snapshot()['quest_update_result'])
            self.assertEqual(session.snapshot()['state'], 'disconnected')

    def test_scope_cannot_upgrade_an_already_bound_session(self):
        session = self.session()
        self.assertEqual(session.snapshot()['coverage']['quest_result'], 'not_verified')
        with patch.object(bounded_world_admission, 'current', return_value=profile()):
            self.receive(session)
        self.assertIsNone(session.snapshot()['quest_update_result'])
        self.assertEqual(session.snapshot()['coverage']['quest_result'], 'not_verified')

    def test_reply_observation_does_not_resolve_a_sent_action(self):
        with patch.object(bounded_world_admission, 'current', return_value=profile()):
            session = self.session()
            key = object()
            session.install_actions(key, contracts={'quest_follow': 'b' * 64})
            offer = dict(kind='quest_follow', context='c' * 64, arguments={'quest_id': '110120'})
            session.offer_actions(key, [offer])
            session.enqueue_action(dict(request_id='d' * 32, **offer,
                policy=dict(skip_dialogues=True, auto_quests=False), origin='manual'))
            session.claim_action(key, context='c' * 64)
            session.action_sent(key, 'd' * 32)
            for code in (0, 10, 0x1197):
                self.receive(session, body(code=code))
            self.assertEqual(session.snapshot()['action_queue']['records'][0]['status'], 'sent')
            self.assertFalse(session.snapshot()['quest_update_result']['action_confirmed'])


if __name__ == '__main__':
    unittest.main()
