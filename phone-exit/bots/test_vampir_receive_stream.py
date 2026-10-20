"""Portable stream integration, including local sockets and character flow."""
from pathlib import Path
import socket
import struct
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.frame_primitives import xor_transform
from vampir_core.key_change import KeyChangePayload
from vampir_core.receive_stream import ReceiveLimits, ReceiveStream, IncomingPacket
from vampir_core.socket_send import drain_outbound
from vampir_core.selection_flow import SelectionState
from test_vampir_selection_flow import connection, list_body, request_fields, FIXTURE


def inner(packet_id, body=b'', key=0):
    payload = struct.pack('<H', packet_id) + body
    return (len(payload) + 3).to_bytes(3, 'little') + xor_transform(payload, key)


def transport(body, compressed=False):
    if compressed:
        size = len(body)
        if size < 15:
            body = bytes([size << 4]) + body
        else:
            extra = size - 15
            body = b'\xf0' + b'\xff' * (extra // 255) + bytes([extra % 255]) + body
    return (len(body) + 3 + (0x800000 if compressed else 0)).to_bytes(3, 'little') + body


def stream(**overrides):
    config = dict(max_transport_size=4096, max_block_output=4096, max_inner_size=4096,
                  max_raw_buffer=8192, max_decoded_buffer=8192)
    config.update(overrides)
    return ReceiveStream(ReceiveLimits(**config))


class ReceiveStreamTests(unittest.TestCase):
    def test_every_socket_cut_at_both_headers_and_bodies(self):
        payload = b'private character data' * 2
        for compressed in (False, True):
            raw = transport(inner(102, payload, 123), compressed)
            for cut in range(len(raw) + 1):
                receiver = stream()
                receiver.feed(raw[:cut])
                first = receiver.next_packet(key_bits=123, max_transport_frames=4)
                if cut < len(raw):
                    self.assertIsNone(first)
                    receiver.feed(raw[cut:])
                    first = receiver.next_packet(key_bits=123, max_transport_frames=4)
                self.assertEqual(first, IncomingPacket(102, payload))
                self.assertEqual((receiver.raw_bytes, receiver.decoded_bytes), (0, 0))
                self.assertNotIn('private', repr(first))

    def test_inner_frame_spans_multiple_compressed_and_raw_blocks(self):
        wire = inner(110, bytes(range(200)))
        receiver = stream()
        for index, byte in enumerate(wire):
            receiver.feed(transport(bytes([byte]), index % 2 == 0))
            packet = receiver.next_packet(key_bits=0, max_transport_frames=1)
            self.assertEqual(packet, IncomingPacket(110, bytes(range(200))) if index == len(wire) - 1 else None)

    def test_coalesced_packets_wait_for_owner_key_rotation(self):
        receiver = stream()
        receiver.feed(transport(inner(11, struct.pack('<Q', 99), 7) + inner(102, b'list', 99), True))
        first = receiver.next_packet(key_bits=7, max_transport_frames=1)
        new_key = KeyChangePayload.decode(first.body).key_bits
        self.assertEqual(first.packet_id, 11)
        self.assertGreater(receiver.decoded_bytes, 0)
        self.assertEqual(receiver.next_packet(key_bits=new_key, max_transport_frames=1), IncomingPacket(102, b'list'))

    def test_transport_work_budget_leaves_complete_raw_tail_for_next_turn(self):
        receiver = stream()
        wire = inner(17, b'ping')
        receiver.feed(b''.join(transport(bytes([byte])) for byte in wire))
        for index in range(len(wire) - 1):
            self.assertIsNone(receiver.next_packet(key_bits=0, max_transport_frames=1))
            self.assertEqual(receiver.decoded_bytes, index + 1)
        self.assertEqual(receiver.next_packet(key_bits=0, max_transport_frames=1), IncomingPacket(17, b'ping'))

    def test_raw_backpressure_does_not_consume_or_close(self):
        receiver = stream(max_transport_size=16, max_raw_buffer=16)
        raw = transport(inner(17, b'12345678'))
        receiver.feed(raw)
        with self.assertRaises(BufferError): receiver.feed(b'next')
        self.assertEqual(receiver.raw_bytes, 16)
        self.assertFalse(receiver.closed)
        self.assertEqual(receiver.next_packet(key_bits=0, max_transport_frames=1), IncomingPacket(17, b'12345678'))
        self.assertEqual(receiver.input_capacity, 16)

    def test_invalid_transport_or_inner_header_is_terminal(self):
        for raw in (b'\0\0\0', b'\xff\xff\x7f', transport(b'\x04\0\0xx'), transport(b'\xff\xff\x7fxx')):
            receiver = stream()
            receiver.feed(raw)
            with self.assertRaises(ValueError): receiver.next_packet(key_bits=0, max_transport_frames=2)
            self.assertTrue(receiver.closed)
            self.assertEqual((receiver.raw_bytes, receiver.decoded_bytes, receiver.input_capacity), (0, 0, 0))
            with self.assertRaises(RuntimeError): receiver.feed(b'anything')

    def test_bad_compression_and_decompression_output_limits(self):
        for raw in ((0x800004).to_bytes(3, 'little') + b'\xf0',
                    transport(inner(17, b'x' * 100), True)):
            receiver = stream(max_block_output=32)
            receiver.feed(raw)
            with self.assertRaisesRegex(ValueError, 'invalid_transport_block'):
                receiver.next_packet(key_bits=0, max_transport_frames=1)
            self.assertTrue(receiver.closed)

    def test_aggregate_decoded_limit_is_enforced(self):
        receiver = stream(max_inner_size=16, max_decoded_buffer=16)
        # Valid incomplete inner frame, followed by a block that would overflow
        # the aggregate decoded buffer before another packet can be extracted.
        receiver.feed(transport(b'\x10\0\0xxx') + transport(bytes(11)))
        with self.assertRaisesRegex(ValueError, 'decoded_buffer_limit'):
            receiver.next_packet(key_bits=0, max_transport_frames=2)
        self.assertEqual(receiver.decoded_bytes, 0)

    def test_eof_drains_complete_packets_then_detects_partial_tail(self):
        for suffix in (b'\x05', transport(inner(102, b'list')[:-1])):
            receiver = stream()
            receiver.feed(transport(inner(17, b'ping')) + suffix)
            receiver.end_input()
            self.assertEqual(receiver.next_packet(key_bits=0, max_transport_frames=2), IncomingPacket(17, b'ping'))
            with self.assertRaisesRegex(ValueError, 'truncated_input'):
                receiver.next_packet(key_bits=0, max_transport_frames=4)
            self.assertFalse(receiver.finished)
        receiver = stream()
        receiver.feed(transport(inner(17)))
        receiver.end_input()
        self.assertFalse(receiver.finished)
        self.assertEqual(receiver.next_packet(key_bits=0, max_transport_frames=1), IncomingPacket(17, b''))
        self.assertTrue(receiver.finished)
        self.assertIsNone(receiver.next_packet(key_bits=0, max_transport_frames=1))
        with self.assertRaises(RuntimeError): receiver.feed(b'')

    def test_close_and_input_validation(self):
        receiver = stream()
        for kwargs in (dict(key_bits=True, max_transport_frames=1), dict(key_bits=0, max_transport_frames=0)):
            with self.assertRaises(ValueError): receiver.next_packet(**kwargs)
        with self.assertRaises(TypeError): receiver.feed(bytearray(b'abc'))
        for options in (dict(max_raw_buffer=1), dict(max_inner_size=4), dict(max_block_output=0), dict(max_transport_size=True)):
            with self.assertRaises(ValueError): stream(**options)
        receiver.feed(b'x')
        receiver.close()
        receiver.close()
        self.assertEqual((receiver.raw_bytes, receiver.decoded_bytes), (0, 0))
        with self.assertRaises(RuntimeError): receiver.next_packet(key_bits=0, max_transport_frames=1)

    def test_local_socket_list_and_select_chain(self):
        flow, queue = connection(key=7, sequence=0)
        receiver = stream()
        client, server = socket.socketpair()
        with client, server:
            client.settimeout(2)
            server.settimeout(2)
            def read_server_request():
                data = bytearray()
                while len(data) < 3 or len(data) < int.from_bytes(data[:3], 'little'):
                    data.extend(server.recv(256))
                return request_fields(bytes(data), 7)
            def receive_response(raw, now):
                server.sendall(raw)
                packet = None
                while packet is None:
                    receiver.feed(client.recv(7))
                    packet = receiver.next_packet(key_bits=7, max_transport_frames=2)
                return flow.receive(packet.packet_id, packet.body, now=now)
            flow.enter_list(now=0)
            drain_outbound(client, queue, max_send_calls=4)
            self.assertEqual(read_server_request(), (101, 0, b''))
            self.assertTrue(receive_response(transport(inner(102, list_body(), 7), True), 1))
            flow.select(flow.preferred_index, now=2)
            drain_outbound(client, queue, max_send_calls=4)
            self.assertEqual(read_server_request(), (109, 1, struct.pack('<QIQ', 22, 0, 42)))
            self.assertTrue(receive_response(transport(inner(110, bytes.fromhex(FIXTURE['select_result_hex']), 7)), 3))
            self.assertEqual(flow.state, SelectionState.SELECT_RESPONSE)
            server.shutdown(socket.SHUT_WR)
            self.assertEqual(client.recv(7), b'')
            receiver.end_input()
            self.assertTrue(receiver.finished)
            flow.close()


if __name__ == '__main__':
    unittest.main()
