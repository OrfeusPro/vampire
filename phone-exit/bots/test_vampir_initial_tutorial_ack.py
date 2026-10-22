"""Explicit command lifecycle; fixtures model server replies, not acceptance."""
import struct
import unittest

import test_vampir_game_connection as connection_tests
from test_vampir_game_connection import BUDGET
from test_vampir_receive_stream import transport, inner
from test_vampir_selection_flow import request_fields
from vampir_core.initial_tutorial_ack import InitialTutorialAck
from vampir_core.outbound import OutboundFrames
from vampir_core.socket_send import drain_outbound
from vampir_core.world_move_start import SOURCE_SHA256


def snapshot(*rows, flag=0):
    if not rows: rows = ((1001, 0, 0, 1),)
    return bytes([flag]) + struct.pack('<H', len(rows)) + b''.join(
        struct.pack('<IIIB', *row) for row in rows)


def response(*, code=0, key=1001, selector=2):
    return struct.pack('<IIIIBBB', code, key, selector, 0, 1, 0, 0)


class InitialTutorialAckTests(unittest.TestCase):
    def flow(self, *, limit=100):
        queue = OutboundFrames(key_bits=7, sequence=65535,
            max_queued_bytes=limit, max_queued_frames=4)
        return InitialTutorialAck(queue, source_sha256=SOURCE_SHA256), queue

    def test_partial_write_early_reply_and_exact_frame_completion(self):
        flow, queue = self.flow()
        flow.receive(9905, snapshot(), now=0)
        flow.queue(now=1)
        class OneByte:
            def __init__(self): self.output = bytearray()
            def send(self, pending):
                self.output.extend(pending[:1])
                return 1
        sock = OneByte()
        sent = []
        def completed(frame):
            sent.append(frame)
            flow.frame_sent(frame)
        drain_outbound(sock, queue, max_send_calls=19, on_frame_sent=completed)
        self.assertEqual(flow.state, 'queued')
        self.assertEqual(sent, [])
        flow.receive(9904, response(), now=2)
        self.assertEqual(flow.state, 'queued')
        drain_outbound(sock, queue, max_send_calls=1, on_frame_sent=completed)
        self.assertEqual(flow.state, 'sent')
        self.assertEqual(len(sent), 1)
        self.assertEqual(request_fields(bytes(sock.output), 7),
            (9903, 65535, struct.pack('<IIB', 1001, 2, 0)))
        self.assertEqual(queue.sequence, 0)
        flow.receive(9904, response(), now=3)
        self.assertEqual((flow.state, flow.result_code, flow.unmatched_results), ('accepted', 0, 1))
        flow.close()
        self.assertEqual(flow.state, 'accepted')
        with self.assertRaises(RuntimeError): flow.queue(now=4)

    def test_refusal_and_unrelated_results_never_trigger_special_retry(self):
        for code in (0, 4223, 7):
            flow, queue = self.flow()
            flow.receive(9905, snapshot(), now=0)
            flow.queue(now=0)
            frame = queue.consume_sent(len(queue.peek_frame()))
            flow.frame_sent(bytes(bytearray(frame)))  # Equal bytes, different frame.
            self.assertEqual(flow.state, 'queued')
            flow.frame_sent(frame)
            for body in (response(key=3001), response(selector=1)):
                flow.receive(9904, body, now=1)
                self.assertEqual(flow.state, 'sent')
            flow.receive(9904, response(code=code), now=2)
            self.assertEqual(flow.state, 'accepted' if code == 0 else 'rejected')
            self.assertEqual(flow.result_code, code)
            self.assertEqual(queue.queued_bytes, 0)
            flow.receive(9905, snapshot(), now=3)
            with self.assertRaises(RuntimeError): flow.queue(now=3)

    def test_eligibility_staleness_and_replacement(self):
        cases = (snapshot((1001, 0, 0, 0)), snapshot((1001, 2, 0, 1)),
            snapshot((1001, 0, 1, 1)), snapshot(flag=1),
            snapshot((1001, 0, 0, 1), (1001, 1, 0, 1)), snapshot((3001, 0, 0, 1)))
        for body in cases:
            flow, queue = self.flow()
            flow.receive(9905, snapshot(), now=0)
            flow.receive(9905, body, now=1)
            with self.assertRaises(RuntimeError): flow.queue(now=1)
            self.assertEqual(queue.queued_bytes, 0)
        flow, _ = self.flow()
        flow.receive(9905, snapshot(), now=0)
        self.assertFalse(flow.expire(now=11))
        self.assertEqual(flow.state, 'waiting_snapshot')
        with self.assertRaises(RuntimeError): flow.queue(now=11)
        flow.receive(9905, snapshot((1001, 1, 0, 1)), now=12)
        flow.queue(now=12)
        self.assertEqual(flow.state, 'queued')

    def test_queue_failure_timeout_close_and_no_replay(self):
        flow, queue = self.flow(limit=19)
        flow.receive(9905, snapshot(), now=0)
        with self.assertRaises(BufferError): flow.queue(now=0)
        self.assertEqual((flow.state, queue.sequence), ('not_queued', 65535))
        with self.assertRaises(RuntimeError): flow.queue(now=0)
        for sent in (False, True):
            flow, queue = self.flow()
            flow.receive(9905, snapshot(), now=0)
            flow.queue(now=1)
            if sent: flow.frame_sent(queue.consume_sent(len(queue.peek_frame())))
            self.assertFalse(flow.expire(now=10))
            self.assertTrue(flow.expire(now=11))
            flow.receive(9904, response(), now=12)
            flow.close()
            self.assertEqual(flow.state, 'unknown')
            with self.assertRaises(RuntimeError): flow.queue(now=12)
        flow, _ = self.flow()
        flow.receive(9905, snapshot(), now=0)
        flow.queue(now=0)
        flow.close()
        self.assertEqual(flow.state, 'unknown')

    def test_source_bodies_and_clock_are_checked(self):
        flow, queue = self.flow()
        with self.assertRaises(ValueError): InitialTutorialAck(queue, source_sha256='0'*64)
        for body in (b'', snapshot()[:-1], snapshot()+b'x'):
            with self.assertRaises(ValueError): flow.receive(9905, body, now=1)
        with self.assertRaises(ValueError): flow.receive(9904, b'', now=1)
        with self.assertRaises(ValueError): flow.expire(now=0)
        for now in (True, -1, float('nan')):
            with self.assertRaises(ValueError): flow.expire(now=now)


class InitialTutorialConnectionTests(unittest.TestCase):
    # Reuse only socket helpers; do not inherit and duplicate the whole suite.
    connect = connection_tests.GameConnectionTests.connect
    read_request = connection_tests.GameConnectionTests.read_request

    def test_default_observation_and_enabling_do_not_send(self):
        for enabled in (False, True):
            events = []
            owner, peer, _ = self.connect(handler=events.append)
            if enabled: owner.enable_initial_tutorial_ack(source_sha256=SOURCE_SHA256)
            peer.sendall(transport(inner(9905, snapshot(), 7)))
            owner.pump(now=0, budget=BUDGET)
            self.assertEqual(owner.queued_bytes, 0)
            self.assertEqual([p.packet_id for p in events], [9905])
            with self.assertRaises(RuntimeError): owner.queue_initial_tutorial_ack(now=0)

    def test_connection_timeout_discards_partial_tail_and_closes(self):
        owner, _, client = self.connect()
        owner.enable_initial_tutorial_ack(source_sha256=SOURCE_SHA256)
        # Exercise owner timeout without fabricating world readiness or sending.
        owner.tutorial_ack.receive(9905, snapshot(), now=0)
        owner.tutorial_ack.queue(now=0)
        owner._outbound.consume_sent(1)
        result = owner.pump(now=10, budget=BUDGET)
        self.assertFalse(result.active)
        self.assertEqual(owner.error, 'initial_tutorial_ack_unknown')
        self.assertEqual(owner.tutorial_ack.state, 'unknown')
        self.assertEqual((owner.queued_bytes, client.fileno()), (0, -1))


if __name__ == '__main__': unittest.main()
