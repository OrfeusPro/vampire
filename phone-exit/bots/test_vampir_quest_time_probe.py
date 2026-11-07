"""First Time step with a current owner and deterministic transport fixtures."""
from pathlib import Path
import socket
import struct
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / 'vampir-shared'))
from vampir_core.bounded_world_admission import SOURCE, TIME_PROBE_POLICY, _active
from vampir_core.character_select_result import WireVector3
from vampir_core.game_connection import GameConnection
from vampir_core.live_session import LiveSession
from vampir_core.quest_record import QuestProgress
from vampir_core.quest_time_probe import QuestTimeProbe
from vampir_core.quest_update import QuestUpdate, encode_quest_update
from vampir_core.quest_update_result import QuestUpdateResult
from vampir_core.world_entry_flow import ServerTargetPosition


POSITION = (132167., 81284., -11010.)


def world():
    bits = struct.unpack('<III', struct.pack('<fff', *POSITION))
    return SimpleNamespace(source_sha256=SOURCE, state='finish_response', finish_result_code=0,
        complete_world=True, target_position=ServerTargetPosition(10010, WireVector3(bits)), close=lambda: None)


def snapshot():
    return dict(state='connected', character=dict(key='123', world_id=10010, hp=2700),
        coverage=dict(quests='last_received_message'),
        quest_snapshot=dict(source_sha256=SOURCE, packet_id=1854, character_key='123', world_id=10010,
                            received_at_ms=time.time_ns() // 1000000),
        quests=[dict(id='110110', state=2, progress=dict(raw08=0))])


class Transport:
    active = True

    def __init__(self):
        self.world_entry = world()
        self.status = 'queued'
        self.bodies = []
        self.released = False

    def queue_tracked_quest_update(self, value, *, source_sha256):
        self.bodies.append(encode_quest_update(value, source_sha256=source_sha256))
        return self

    def quest_send_status(self, ticket):
        assert ticket is self
        return self.status

    def release_quest_send(self, ticket):
        assert ticket is self
        self.released = True


class QuestTimeProbeTests(unittest.TestCase):
    def setUp(self):
        token = _active.set(dict(source_sha256=SOURCE, policies=[TIME_PROBE_POLICY]))
        self.addCleanup(_active.reset, token)

    def begin(self, data=None):
        probe, connection = QuestTimeProbe(source_sha256=SOURCE), Transport()
        data = snapshot() if data is None else data
        probe.tick(data, connection, now=0.)
        self.assertEqual(connection.bodies, [])
        probe.tick(data, connection, now=.1)
        return probe, connection

    def test_one_frame_and_correlated_advance(self):
        probe, connection = self.begin()
        reply = QuestUpdateResult(0, 110110, 2, QuestProgress(1, 0, 0))
        self.assertFalse(probe.receive(reply, character_key=123, world_id=10010, now=.2))
        connection.status = 'socket_accepted'
        self.assertFalse(probe.receive(reply, character_key=124, world_id=10010, now=.2))
        self.assertFalse(probe.receive(reply, character_key=123, world_id=10011, now=.2))
        other = QuestUpdateResult(0, 110120, 2, QuestProgress(1, 0, 0))
        self.assertFalse(probe.receive(other, character_key=123, world_id=10010, now=.2))
        self.assertTrue(probe.receive(reply, character_key=123, world_id=10010, now=.2))
        probe.tick(snapshot(), connection, now=1.)
        self.assertEqual(connection.bodies, [struct.pack('<fffQQB', *POSITION, 0, 110110, 0)])
        self.assertTrue(connection.released)
        report = probe.snapshot()
        self.assertEqual(report['state'], 'advanced')
        self.assertEqual(report['position_source'], 'world_move_finish_result')
        self.assertFalse(report['actor_vector_verified'])
        self.assertFalse(report['quest_completed'])

    def test_freshness_health_world_and_step_fences(self):
        for change in ('stale', 'dead', 'other_world', 'other_index', 'not_started', 'duplicate', 'start_reply'):
            data = snapshot()
            if change == 'stale': data['quest_snapshot']['received_at_ms'] -= 31000
            if change == 'dead': data['character']['hp'] = 0
            if change == 'other_world': data['character']['world_id'] = 10011
            if change == 'other_index': data['quests'][0]['progress']['raw08'] = 1
            if change == 'not_started': data['quests'][0]['state'] = 1
            if change == 'duplicate': data['quests'] *= 2
            if change == 'start_reply': data['quest_snapshot']['packet_id'] = 1804
            with self.subTest(change=change):
                _, connection = self.begin(data)
                self.assertEqual(connection.bodies, [])

    def test_uncertain_or_rejected_action_never_repeats(self):
        for case in ('timeout', 'closed', 'malformed', 'rejected', 'same_index'):
            with self.subTest(case=case):
                probe, connection = self.begin()
                connection.status = 'socket_accepted'
                if case == 'timeout':
                    probe.tick(snapshot(), connection, now=20.)
                elif case == 'closed':
                    probe.close()
                else:
                    reply = None if case == 'malformed' else QuestUpdateResult(
                        20 if case == 'rejected' else 0, 110110, 2, QuestProgress(0, 0, 0))
                    probe.receive(reply, character_key=123, world_id=10010, now=.2)
                probe.tick(snapshot(), connection, now=21.)
                self.assertEqual(len(connection.bodies), 1)
                self.assertEqual(probe.state, {'rejected': 'rejected', 'same_index': 'accepted_without_advance'}.get(
                    case, 'outcome_unknown'))

    def test_current_connection_rejects_other_vector_and_task(self):
        from vampir_core.receive_stream import ReceiveLimits
        from vampir_core.selection_flow import SelectionLimits
        local, peer = socket.socketpair()
        self.addCleanup(local.close)
        self.addCleanup(peer.close)
        owner = GameConnection(local, key_bits=123, sequence=0,
            receive_limits=ReceiveLimits(4096, 4096, 4096, 8192, 8192),
            selection_limits=SelectionLimits(4096, 4, 64, 10),
            max_queued_bytes=128, max_queued_frames=1, on_packet=lambda _: None)
        self.addCleanup(owner.close)
        owner._world_entry = world()
        for vector, quest, index in (((0., 0., 0.), 110110, 0), (POSITION, 110120, 0), (POSITION, 110110, 1)):
            with self.assertRaises(ValueError):
                owner.queue_tracked_quest_update(QuestUpdate(vector, 0, quest, index), source_sha256=SOURCE)
        self.assertEqual(owner.queued_bytes, 0)
        owner.queue_tracked_quest_update(QuestUpdate(POSITION, 0, 110110, 0), source_sha256=SOURCE)
        self.assertGreater(owner.queued_bytes, 0)

    def test_live_packet_dispatch_keeps_probe_result_separate(self):
        probe, connection = self.begin()
        connection.status = 'socket_accepted'
        session = LiveSession(bot_id='time-fixture', quest_time_probe=True)
        with patch('vampir_core.live_session.quest_reply_observation_permitted', return_value=True):
            session.bind_source(SOURCE)
        session._snapshot.update(snapshot())
        session._time_probe = probe
        body = struct.pack('<IQBBQQ', 0, 110110, 2, 1, 0, 0)
        with patch('vampir_core.quest_update_result.quest_reply_observation_permitted', return_value=True), \
                patch('vampir_core.live_session.time.monotonic', return_value=.2):
            session.packet(1811, body, character_key=123, world_id=10010)
        observed = session.snapshot()
        self.assertEqual(observed['quest_time_probe']['state'], 'advanced')
        self.assertEqual(observed['quests'][0]['progress']['raw08'], 0)
        self.assertEqual(observed['quest_update_result']['progress']['raw08'], 1)


if __name__ == '__main__':
    unittest.main()
