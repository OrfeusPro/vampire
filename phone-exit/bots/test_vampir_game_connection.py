"""Connected socket owner integration without a game or external network."""
import socket
import select
import struct
import unittest

from test_vampir_receive_stream import transport, inner
from test_vampir_selection_flow import list_body, FIXTURE, request_fields
from vampir_core.game_connection import GameConnection, PumpBudget
from vampir_core.receive_stream import ReceiveLimits
from vampir_core.selection_flow import SelectionLimits, SelectionState
from vampir_core.ping import PingPayload

BUDGET = PumpBudget(4, 4, 4, 64, 4)


class GameConnectionTests(unittest.TestCase):
    def connect(self, *, handler=None, queue_bytes=8192):
        client, server = socket.socketpair()
        server.settimeout(2)
        self.addCleanup(server.close)
        owner = GameConnection(client, key_bits=7, sequence=0,
            receive_limits=ReceiveLimits(4096, 4096, 4096, 8192, 8192),
            selection_limits=SelectionLimits(4096, 4, 64, 10),
            max_queued_bytes=queue_bytes, max_queued_frames=8,
            on_packet=handler or (lambda packet: None))
        self.addCleanup(owner.close)
        return owner, server, client

    def read_request(self, server, key):
        data = bytearray()
        while len(data) < 3 or len(data) < int.from_bytes(data[:3], 'little'):
            # Read only the remainder of this frame, preserving later frames.
            wanted = 3 - len(data) if len(data) < 3 else int.from_bytes(data[:3], 'little') - len(data)
            data.extend(server.recv(wanted))
        return request_fields(bytes(data), key)

    def test_socket_owner_full_list_select_and_eof(self):
        owner, server, client = self.connect()
        owner.enter_character_list(now=0)
        owner.pump(now=0, budget=BUDGET)
        self.assertEqual(self.read_request(server, 7), (101, 0, b''))
        server.sendall(transport(inner(102, list_body(), 7), True))
        for _ in range(20):
            owner.pump(now=1, budget=BUDGET)
            if owner.selection.state == SelectionState.LIST_AVAILABLE: break
        self.assertEqual(owner.selection.preferred_index, 1)
        owner.select_character(1, now=2)
        owner.pump(now=2, budget=BUDGET)
        self.assertEqual(self.read_request(server, 7), (109, 1, struct.pack('<QIQ', 22, 0, 42)))
        server.sendall(transport(inner(110, bytes.fromhex(FIXTURE['select_result_hex']), 7)))
        for _ in range(20):
            owner.pump(now=3, budget=BUDGET)
            if owner.selection.state == SelectionState.SELECT_RESPONSE: break
        self.assertEqual(owner.selection.state, SelectionState.SELECT_RESPONSE)
        server.shutdown(socket.SHUT_WR)
        owner.pump(now=4, budget=BUDGET)
        self.assertFalse(owner.active)
        self.assertIsNone(owner.error)
        self.assertEqual(client.fileno(), -1)
        self.assertIsNone(owner.selection.characters)

    def test_coalesced_key_rotation_before_next_packet_and_ack(self):
        events = []
        owner, server, _ = self.connect(handler=events.append)
        server.sendall(transport(inner(11, struct.pack('<Q', 99), 7) + inner(444, b'second', 99), True))
        progress = owner.pump(now=0, budget=BUDGET)
        self.assertEqual(progress.packets, 2)
        self.assertEqual([(e.packet_id, e.body) for e in events], [(444, b'second')])
        self.assertEqual(self.read_request(server, 7), (12, 0, struct.pack('<Q', 99)))
        owner.enter_character_list(now=1)
        owner.pump(now=1, budget=BUDGET)
        self.assertEqual(self.read_request(server, 99), (101, 1, b''))
        self.assertNotIn('99', repr(owner))

    def test_packet_budget_keeps_buffered_work_for_next_pump(self):
        events = []
        owner, server, _ = self.connect(handler=events.append)
        server.sendall(transport(inner(444, b'a', 7) + inner(445, b'b', 7)))
        tiny = PumpBudget(1, 1, 1, 1024, 1)
        self.assertEqual(owner.pump(now=0, budget=tiny).packets, 1)
        self.assertEqual(owner.pump(now=1, budget=tiny).packets, 1)
        self.assertEqual([e.packet_id for e in events], [444, 445])

    def test_timeout_closes_socket_and_discards_unsent_request(self):
        owner, server, client = self.connect()
        owner.enter_character_list(now=0)
        result = owner.pump(now=10, budget=BUDGET)
        self.assertFalse(result.active)
        self.assertEqual(owner.error, 'selection_timeout')
        self.assertEqual((owner.queued_bytes, client.fileno()), (0, -1))
        self.assertEqual(server.recv(32), b'')
        with self.assertRaises(RuntimeError): owner.enter_character_list(now=11)

    def test_malformed_key_and_failed_ack_are_terminal(self):
        for body, limit in ((b'private', 8192), (struct.pack('<Q', 99), 10)):
            owner, server, client = self.connect(queue_bytes=limit)
            server.sendall(transport(inner(11, body, 7)))
            with self.assertRaisesRegex(RuntimeError, '^Game connection processing failed$'):
                owner.pump(now=0, budget=BUDGET)
            self.assertFalse(owner.active)
            self.assertEqual((owner.queued_bytes, client.fileno()), (0, -1))

    def test_error_response_closes_connection_without_retry(self):
        owner, server, client = self.connect()
        owner.enter_character_list(now=0)
        server.sendall(transport(inner(102, list_body(code=14), 7)))
        self.assertFalse(owner.pump(now=1, budget=PumpBudget(4, 4, 4, 4096, 4)).active)
        self.assertEqual(owner.error, 'selection_response_failed')
        self.assertEqual(owner.selection.result_code, 14)
        self.assertEqual(owner.queued_bytes, 0)
        self.assertEqual(server.recv(32), b'')

    def test_eof_partial_and_callback_failure_close_everything(self):
        owner, server, client = self.connect()
        server.sendall(b'\x10')
        server.shutdown(socket.SHUT_WR)
        # Windows socketpair shutdown can become readable in a later pump.
        with self.assertRaises(RuntimeError):
            for _ in range(20):
                select.select([client], [], [], .1)
                owner.pump(now=0, budget=BUDGET)
        self.assertEqual(client.fileno(), -1)
        def fail(packet): raise ValueError('sensitive callback details')
        owner, server, client = self.connect(handler=fail)
        server.sendall(transport(inner(444, b'secret', 7)))
        with self.assertRaisesRegex(RuntimeError, '^Game connection processing failed$'):
            owner.pump(now=0, budget=BUDGET)
        self.assertFalse(owner.active)

    def test_idle_nonblocking_clock_and_budget_validation(self):
        owner, _, _ = self.connect()
        result = owner.pump(now=1, budget=BUDGET)
        self.assertEqual((result.packets, result.bytes_received, result.bytes_sent, result.active), (0, 0, 0, True))
        with self.assertRaises(ValueError): owner.pump(now=0, budget=BUDGET)
        with self.assertRaises(ValueError): PumpBudget(0, 1, 1, 1, 1)
        self.assertTrue(owner.active)

    def test_explicit_ping_and_external_flow_close(self):
        owner, server, client = self.connect()
        owner.queue_ping(PingPayload(1, 2))
        owner.pump(now=0, budget=BUDGET)
        self.assertEqual(self.read_request(server, 7), (16, 0, struct.pack('<QQ', 1, 2)))
        owner.selection.close()
        self.assertFalse(owner.pump(now=1, budget=BUDGET).active)
        self.assertEqual(client.fileno(), -1)


if __name__ == '__main__': unittest.main()
