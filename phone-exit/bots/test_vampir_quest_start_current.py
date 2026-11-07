"""Manual current QuestStart fences; all transports here are explicit fixtures."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.bounded_world_admission import _active
from vampir_core.quest_start import SOURCE, encode_quest_start, decode_quest_start_result
from vampir_core.quest_start_flow import ManualQuestStart
from vampir_core.outbound import OutboundFrames


def body(code=0, key=110110, state=2):
    return struct.pack('<IQHBH', code, key, 1, 0, 1) + struct.pack(
        '<QBBQQBIII', key, state, 0, 0, 0, 0, 0, 0, 0) + struct.pack('<Q', 0)


class Connection:
    active = True
    def __init__(self):
        self.calls, self.transport = 0, 'queued'
    def queue_tracked_quest_start(self, key, **kwargs):
        self.calls += 1
        return self
    def quest_send_status(self, ticket):
        if ticket is not self:
            raise ValueError('fixture ticket')
        return self.transport


def snapshot():
    return dict(state='connected', source_sha256=SOURCE,
        character=dict(key='123', world_id=10010, hp=2700),
        coverage=dict(quests='last_received_message'),
        quest_snapshot=dict(character_key='123', world_id=10010, source_sha256=SOURCE,
                            received_at_ms=time.time_ns() // 1000000),
        quests=[dict(id='110110', state=1)])


class QuestStartTests(unittest.TestCase):
    def setUp(self):
        self.token = _active.set(dict(source_sha256=SOURCE,
            policies=['quest-observation-v1', 'quest-start-manual-v1']))
    def tearDown(self):
        _active.reset(self.token)
    def begin(self):
        flow, connection = ManualQuestStart(110110, source_sha256=SOURCE), Connection()
        flow.tick(snapshot(), connection, now=time.monotonic())
        return flow, connection
    def test_wire_key_only(self):
        self.assertEqual(encode_quest_start(110110, source_sha256=SOURCE), struct.pack('<Q', 110110))
        for value in (0, -1, True, '110110', 2**64):
            with self.assertRaises(ValueError): encode_quest_start(value, source_sha256=SOURCE)
    def test_source_fence(self):
        with self.assertRaises(ValueError): encode_quest_start(110110, source_sha256='0' * 64)
        _active.set(None)
        with self.assertRaises(ValueError): ManualQuestStart(110110, source_sha256=SOURCE)
    def test_full_nested_result(self):
        result = decode_quest_start_result(body(), source_sha256=SOURCE)
        self.assertEqual((result.result_code, result.quest_id, result.data.groups[0].quests[0].raw10), (0, 110110, 2))
    def test_truncated_and_trailing(self):
        raw = body()
        for size in range(len(raw)):
            with self.subTest(size=size), self.assertRaises((ValueError, BufferError)):
                decode_quest_start_result(raw[:size], source_sha256=SOURCE)
        with self.assertRaises(ValueError): decode_quest_start_result(raw + b'X', source_sha256=SOURCE)
    def test_collection_budget(self):
        with self.assertRaises(BufferError):
            decode_quest_start_result(struct.pack('<IQH', 0, 110110, 9) + bytes(8), source_sha256=SOURCE)
    def test_one_send_only(self):
        flow, connection = self.begin()
        for _ in range(20): flow.tick(snapshot(), connection, now=time.monotonic())
        self.assertEqual((connection.calls, flow.state), (1, 'queued'))
    def test_complete_socket_before_result(self):
        flow, connection = self.begin()
        self.assertFalse(flow.receive(body(), character_key=123, world_id=10010))
        connection.transport = 'socket_accepted'
        self.assertTrue(flow.receive(body(), character_key=123, world_id=10010))
        self.assertEqual(flow.state, 'started')
        self.assertFalse(flow.result['quest_completed'])
        self.assertFalse(flow.receive(body(), character_key=123, world_id=10010))
        self.assertEqual(connection.calls, 1)
    def test_rejected_response(self):
        flow, connection = self.begin(); connection.transport = 'socket_accepted'
        flow.receive(body(code=100), character_key=123, world_id=10010)
        self.assertEqual(flow.state, 'rejected')
        flow.tick(snapshot(), connection, now=time.monotonic())
        self.assertEqual(connection.calls, 1)
    def test_uncorrelated_response(self):
        flow, connection = self.begin(); connection.transport = 'socket_accepted'
        for raw, key, world in ((body(key=110120), 123, 10010), (body(), 124, 10010), (body(), 123, 10012)):
            self.assertFalse(flow.receive(raw, character_key=key, world_id=world))
        self.assertEqual(flow.unmatched, 3)
        self.assertIsNone(flow.result)
    def test_timeout_no_retry(self):
        flow, connection = self.begin()
        flow.tick(snapshot(), connection, now=flow.deadline)
        connection.transport = 'socket_accepted'
        self.assertFalse(flow.receive(body(), character_key=123, world_id=10010))
        self.assertEqual((flow.state, connection.calls), ('outcome_unknown', 1))
    def test_late_result_fence(self):
        flow, connection = self.begin(); connection.transport = 'socket_accepted'
        with patch('vampir_core.quest_start_flow.time.monotonic', return_value=flow.deadline):
            self.assertFalse(flow.receive(body(), character_key=123, world_id=10010))
        self.assertEqual(flow.state, 'outcome_unknown')
    def test_invalid_result_no_retry(self):
        flow, connection = self.begin(); connection.transport = 'socket_accepted'
        flow.receive(b'bad', character_key=123, world_id=10010)
        flow.tick(snapshot(), connection, now=time.monotonic())
        self.assertEqual((flow.state, flow.decode_errors, connection.calls), ('outcome_unknown', 1, 1))
    def test_other_states_zero_sends(self):
        for state in (0, 2, 4, 5, 6):
            flow, connection, data = ManualQuestStart(110110, source_sha256=SOURCE), Connection(), snapshot()
            data['quests'][0]['state'] = state
            flow.tick(data, connection, now=time.monotonic())
            self.assertEqual(connection.calls, 0)
    def test_stale_missing_dead_scope(self):
        for change in ('stale', 'missing', 'dead', 'world', 'duplicate'):
            flow, connection, data = ManualQuestStart(110110, source_sha256=SOURCE), Connection(), snapshot()
            if change == 'stale': data['quest_snapshot']['received_at_ms'] -= 31000
            if change == 'missing': data['quests'] = []
            if change == 'dead': data['character']['hp'] = 0
            if change == 'world': data['character']['world_id'] = 10012
            if change == 'duplicate': data['quests'] *= 2
            flow.tick(data, connection, now=time.monotonic())
            self.assertEqual(connection.calls, 0)
    def test_stop_and_world_change(self):
        flow, connection = self.begin(); flow.close()
        flow.tick(snapshot(), connection, now=time.monotonic())
        self.assertEqual((flow.state, connection.calls), ('outcome_unknown', 1))
        flow, connection = self.begin(); data = snapshot(); data['character']['world_id'] = 10012
        flow.tick(data, connection, now=time.monotonic())
        self.assertEqual((flow.state, connection.calls), ('scope_changed', 1))
    def test_outbound_backpressure_sequence(self):
        q = OutboundFrames(key_bits=123, sequence=65535, max_queued_bytes=64, max_queued_frames=1)
        frame = q.queue_quest_start(110110, source_sha256=SOURCE)
        self.assertEqual(q.sequence, 0)
        with self.assertRaises(BufferError): q.queue_quest_start(110110, source_sha256=SOURCE)
        self.assertEqual(q.sequence, 0)
        self.assertIsNone(q.consume_sent(3))
        self.assertIs(q.consume_sent(len(frame) - 3), frame)
    def test_inactive_connection(self):
        flow, connection = self.begin(); connection.active = False
        flow.tick(snapshot(), connection, now=time.monotonic())
        self.assertEqual((flow.state, connection.calls), ('connection_lost', 1))


class QuestStartProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = HERE / 'resource-tools/vampir/verify-quest-start-current.py'
        spec = importlib.util.spec_from_file_location('quest_start_proof_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.pointer = cls.tool.verify()
        cls.report = json.loads(Path(cls.pointer['report']).read_bytes())

    def test_retained_nested_reader_and_exact_matrix(self):
        self.tool.validate(self.report, self.report['definition'])
        self.assertEqual(self.report['definition']['nested_proof']['sha256'],
            '90eb396d3744175bf1af9a360e9fad479a89801f417ae35e245df9c20b69bd80')
        self.assertFalse(self.report['quest_completed'])
        self.assertFalse(self.report['runtime_admitted'])

    def test_missing_duplicate_or_forged_native_outcome_rejected(self):
        for change in ('missing', 'duplicate', 'outcome', 'abi', 'scope'):
            report = copy.deepcopy(self.report)
            if change == 'missing': report['result']['eligibility'].pop()
            if change == 'duplicate': report['result']['requests'][1] = report['result']['requests'][0]
            if change == 'outcome': report['result']['producers'][0]['sent'] = True
            if change == 'abi': report['result']['native_entries']['0x145d72d80'] = 0
            if change == 'scope': report['quest_completed'] = True
            with self.assertRaises(ValueError): self.tool.validate(report, self.report['definition'])

    def test_unchanged_proof_needs_no_native_or_process(self):
        sys.path.insert(0, str(HERE.parent / '.tools/vampir-analysis'))
        from unicorn import Uc
        with patch.object(Uc, 'emu_start', side_effect=AssertionError('Unexpected native replay')), \
                patch('subprocess.Popen', side_effect=AssertionError('Unexpected process')):
            result = self.tool.verify()
        self.assertTrue(result['reused'])
        self.assertEqual(result['sha256'], self.pointer['sha256'])


if __name__ == '__main__':
    unittest.main()
