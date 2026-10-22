"""One reset-field diagnostic, no retry after uncertain transport outcome."""
import unittest
import test_vampir_game_connection as connection_tests

from test_vampir_quest_list import fixture
from vampir_core.quest_list_flow import QuestListRead
from vampir_core.outbound import OutboundFrames
from vampir_core.socket_send import drain_outbound
from vampir_core.world_move_start import SOURCE_SHA256


class QuestListFlowTests(unittest.TestCase):
    def flow(self, *, limit=100):
        queue = OutboundFrames(key_bits=7, sequence=0, max_queued_bytes=limit, max_queued_frames=2)
        return QuestListRead(queue, source_sha256=SOURCE_SHA256, timeout=2), queue

    def test_partial_send_early_wrong_type_and_completion(self):
        flow, queue = self.flow()
        flow.queue(now=0)
        class OneByte:
            def send(self, data): return 1
        drain_outbound(OneByte(), queue, max_send_calls=19, on_frame_sent=flow.frame_sent)
        flow.receive(fixture(), now=0)
        self.assertEqual(flow.state, 'queued')
        self.assertIsNone(flow.response)
        drain_outbound(OneByte(), queue, max_send_calls=1, on_frame_sent=flow.frame_sent)
        self.assertEqual(flow.state, 'sent')
        body = bytearray(fixture());body[4] = 1
        flow.receive(bytes(body), now=0)
        self.assertEqual(flow.state, 'sent')
        flow.receive(fixture(), now=1)
        self.assertEqual((flow.state, flow.result_code, flow.unmatched_results), ('received', 0, 2))
        self.assertEqual(flow.response.item_changes.counts, (0, 0, 0, 0))
        with self.assertRaises(RuntimeError): flow.queue(now=1)
        flow.close()
        self.assertIsNone(flow.response)

    def test_rejection_timeout_and_queue_failure(self):
        flow, queue = self.flow()
        flow.queue(now=0)
        flow.frame_sent(queue.consume_sent(20))
        body = bytearray(fixture());body[0] = 9
        flow.receive(bytes(body), now=1)
        self.assertEqual((flow.state, flow.result_code), ('rejected', 9))
        for sent in (False, True):
            flow, queue = self.flow()
            flow.queue(now=0)
            if sent: flow.frame_sent(queue.consume_sent(20))
            self.assertTrue(flow.expire(now=2))
            flow.receive(fixture(), now=2)
            self.assertEqual(flow.state, 'unknown')
            with self.assertRaises(RuntimeError): flow.queue(now=2)
        flow, queue = self.flow(limit=19)
        with self.assertRaises(BufferError): flow.queue(now=0)
        self.assertEqual((flow.state, queue.sequence), ('not_queued', 0))
        with self.assertRaises(RuntimeError): flow.queue(now=0)

    def test_source_clock_close_and_malformed_result(self):
        flow, queue = self.flow()
        with self.assertRaises(ValueError): QuestListRead(queue, source_sha256='old', timeout=2)
        for timeout in (True, 0, 31, float('nan')):
            with self.assertRaises(ValueError): QuestListRead(queue, source_sha256=SOURCE_SHA256, timeout=timeout)
        with self.assertRaises(ValueError): flow.receive(b'', now=0)
        flow.queue(now=1)
        with self.assertRaises(ValueError): flow.expire(now=0)
        flow.close()
        flow.receive(fixture(), now=1)
        self.assertEqual(flow.state, 'unknown')
        self.assertIsNone(flow.response)


class QuestConnectionTests(unittest.TestCase):
    connect = connection_tests.GameConnectionTests.connect

    def test_world_guard_and_timeout_discard_unsent_tail(self):
        owner, _, client = self.connect()
        owner.enable_quest_list_read(source_sha256=SOURCE_SHA256, timeout=2)
        with self.assertRaises(RuntimeError): owner.queue_quest_list_read(now=0)
        self.assertEqual(owner.queued_bytes, 0)
        # Arrange the internal queue solely to exercise connection cleanup;
        # this is not a fabricated successful world-entry scenario.
        owner.quest_list.queue(now=0)
        owner._outbound.consume_sent(1)
        result = owner.pump(now=2, budget=connection_tests.BUDGET)
        self.assertFalse(result.active)
        self.assertEqual(owner.error, 'quest_list_unknown')
        self.assertEqual(owner.quest_list.state, 'unknown')
        self.assertEqual((owner.queued_bytes, client.fileno()), (0, -1))


if __name__ == '__main__': unittest.main()
