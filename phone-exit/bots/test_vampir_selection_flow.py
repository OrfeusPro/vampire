"""Portable lifecycle checks and frozen synthetic native frame vectors."""
import json
from pathlib import Path
import struct
import sys
import unittest
import zlib

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.character_select import CharacterSelectPayload
from vampir_core.frame_primitives import xor_transform
from vampir_core.outbound import OutboundFrames
from vampir_core.key_change import KeyChangePayload
from vampir_core.selection_flow import CharacterSelectionFlow, SelectionLimits, SelectionState
from vampir_core.send_frame import encode_character_list_frame_b, encode_character_select_frame_b

FIXTURE = json.loads((HERE / 'fixtures/vampir-selection-flow.json').read_text('utf-8'))


def list_body(keys=(11, 22), preferred=22, context=42, code=0):
    # Full verified record order, empty strings/extensions and absent optional.
    def record(key):
        q, i, text = struct.pack('<Q', key), struct.pack('<I', key & 0xffffffff), b'\0\0'
        appearance = bytes(10) + text + bytes(4)
        return q + i + text + q + i + q + q + text + b'\0' + q * 6 + appearance + q * 3 + bytes(2)
    return (struct.pack('<IIH', code, 207, len(keys)) + b''.join(record(k) for k in keys)
            + struct.pack('<QIQQ', 0, 23, preferred, context))


def connection(*, sequence=65535, key=0x0102030405060708, max_bytes=8192, max_frames=8, **limits):
    outbound = OutboundFrames(key_bits=key, sequence=sequence, max_queued_bytes=max_bytes, max_queued_frames=max_frames)
    config = dict(max_payload_size=4096, max_characters=4, max_collection_items=64, request_timeout=10)
    config.update(limits)
    return CharacterSelectionFlow(outbound, SelectionLimits(**config)), outbound


def request_fields(frame, key):
    plain = xor_transform(frame[3:], key)
    crc, packet_id, sequence = struct.unpack_from('<IHH', plain)
    if zlib.crc32(plain[4:]) != crc:
        raise AssertionError('Invalid outbound CRC')
    if len(frame) != int.from_bytes(frame[:3], 'little'):
        raise AssertionError('Invalid outbound size')
    return packet_id, sequence, plain[8:]


class SelectionFlowTests(unittest.TestCase):
    def test_frames_match_all_19_frozen_native_vectors(self):
        self.assertTrue(FIXTURE['synthetic_only'])
        self.assertEqual(len(FIXTURE['frames']), 19)
        for row in FIXTURE['frames']:
            if row['packet_id'] == 101:
                frame = encode_character_list_frame_b(row['sequence'], row['key'])
            else:
                frame = encode_character_select_frame_b(CharacterSelectPayload(*row['fields']), row['sequence'], row['key'])
            self.assertEqual(frame.hex(), row['frame_hex'])

    def test_list_select_response_partial_send_and_sequence_wrap(self):
        flow, queue = connection()
        self.assertEqual(flow.state, SelectionState.WAITING_ENTRY)
        self.assertIsNone(queue.peek_frame())
        flow.enter_list(now=1)
        first = bytes(queue.peek_frame())
        queue.consume_sent(2)
        self.assertEqual(bytes(queue.peek_frame()), first[2:])
        queue.consume_sent(len(first) - 2)
        self.assertEqual(request_fields(first, 0x0102030405060708), (101, 65535, b''))
        self.assertEqual(queue.sequence, 0)
        self.assertTrue(flow.receive(102, list_body(), now=2))
        self.assertEqual((flow.state, flow.preferred_index, flow.deadline), (SelectionState.LIST_AVAILABLE, 1, None))
        flow.select(flow.preferred_index, now=3)
        frame = queue.pop_frame()
        packet_id, sequence, body = request_fields(frame, 0x0102030405060708)
        self.assertEqual((packet_id, sequence, struct.unpack('<QIQ', body)), (109, 0, (22, 0, 42)))
        self.assertTrue(flow.receive(110, bytes.fromhex(FIXTURE['select_result_hex']), now=4))
        self.assertEqual(flow.state, SelectionState.SELECT_RESPONSE)
        self.assertEqual(flow.response.result_code, 0)
        self.assertIsNone(flow.deadline)
        # No automatic world completion packet or session-ready transition.
        self.assertEqual(queue.queued_frames, 0)
        with self.assertRaises(RuntimeError): flow.select(0, now=5)

    def test_context_update_overrides_old_list_tail(self):
        flow, queue = connection(key=0)
        flow.enter_list(now=0)
        queue.pop_frame()
        flow.receive(102, list_body(), now=1)
        flow.update_raw_f0(2**64 - 1)
        flow.select(0, now=2)
        body = request_fields(queue.pop_frame(), 0)[2]
        self.assertEqual(struct.unpack('<QIQ', body), (11, 0, 2**64 - 1))

    def test_selection_uses_current_connection_key_after_ack(self):
        flow, queue = connection(key=7, sequence=10)
        flow.enter_list(now=0)
        request = queue.pop_frame()
        self.assertEqual(request_fields(request, 7)[:2], (101, 10))
        queue.acknowledge_key_change(KeyChangePayload(99))
        flow.receive(102, list_body(), now=1)
        flow.select(1, now=2)
        ack, selection = queue.pop_frame(), queue.pop_frame()
        self.assertEqual(request_fields(ack, 7), (12, 11, struct.pack('<Q', 99)))
        self.assertEqual(request_fields(selection, 99), (109, 12, struct.pack('<QIQ', 22, 0, 42)))

    def test_queue_refusal_never_creates_pending_request_or_consumes_sequence(self):
        flow, queue = connection(max_bytes=10)
        with self.assertRaises(BufferError): flow.enter_list(now=1)
        self.assertEqual((flow.state, flow.deadline, queue.sequence, queue.queued_frames),
                         (SelectionState.WAITING_ENTRY, None, 65535, 0))
        flow, queue = connection(max_frames=1)
        flow.enter_list(now=0)
        # Deliberately keep the full list request queued to force select refusal.
        flow.receive(102, list_body(), now=1)
        with self.assertRaises(BufferError): flow.select(0, now=2)
        self.assertEqual((flow.state, flow.deadline, queue.sequence), (SelectionState.LIST_AVAILABLE, None, 0))
        queue.pop_frame()
        flow.select(0, now=3)
        self.assertEqual(queue.sequence, 1)

    def test_duplicate_or_unsolicited_selection_packets_do_not_advance(self):
        flow, queue = connection()
        with self.assertRaises(RuntimeError): flow.receive(102, list_body(), now=0)
        with self.assertRaises(RuntimeError): flow.select(0, now=0)
        flow.enter_list(now=1)
        with self.assertRaises(RuntimeError): flow.enter_list(now=1)
        with self.assertRaises(RuntimeError): flow.receive(110, bytes.fromhex(FIXTURE['select_result_hex']), now=2)
        self.assertFalse(flow.receive(17, b'opaque', now=2))
        self.assertEqual((flow.state, queue.queued_frames), (SelectionState.LIST_PENDING, 1))
        flow.receive(102, list_body(), now=3)
        with self.assertRaises(RuntimeError): flow.receive(102, list_body(), now=3)
        self.assertEqual(queue.queued_frames, 1)

    def test_timeout_discards_partially_sent_request_and_late_reply(self):
        flow, queue = connection()
        flow.enter_list(now=5)
        queue.consume_sent(3)
        self.assertFalse(flow.expire(now=14.9))
        self.assertFalse(flow.receive(102, list_body(), now=15))
        self.assertEqual((flow.state, flow.error, queue.queued_bytes), (SelectionState.FAILED, 'request_timeout', 0))
        self.assertIsNone(queue.peek_frame())
        with self.assertRaises(RuntimeError): flow.receive(102, list_body(), now=16)
        with self.assertRaises(RuntimeError): queue.queue_character_list()

    def test_disconnect_invalidates_queue_and_drops_old_character_data(self):
        flow, queue = connection()
        flow.enter_list(now=0)
        flow.receive(102, list_body(), now=1)
        flow.select(1, now=2)
        flow.close()
        flow.close()
        self.assertEqual((flow.state, queue.queued_frames, queue.queued_bytes), (SelectionState.CLOSED, 0, 0))
        self.assertIsNone(flow.characters)
        self.assertIsNone(flow.response)
        with self.assertRaises(RuntimeError): queue.queue_character_list()
        new_flow, new_queue = connection(sequence=0)
        with self.assertRaises(RuntimeError): new_flow.select(1, now=3)
        self.assertEqual(new_queue.sequence, 0)

    def test_empty_list_and_invalid_index_never_send_selection(self):
        for keys, index in (((), 0), ((11,), -1), ((11,), 1), ((11,), True)):
            flow, queue = connection()
            flow.enter_list(now=0)
            queue.pop_frame()
            flow.receive(102, list_body(keys), now=1)
            with self.assertRaises(ValueError): flow.select(index, now=2)
            self.assertEqual((flow.state, queue.queued_frames, queue.sequence), (SelectionState.LIST_AVAILABLE, 0, 0))

    def test_malformed_and_over_budget_replies_fail_without_body_in_errors(self):
        for body, limit in ((b'private-data', 4), (list_body(), 1), (list_body() + b'extra', 4)):
            flow, queue = connection(max_characters=limit)
            flow.enter_list(now=0)
            with self.assertRaisesRegex(ValueError, '^Invalid selection response$'):
                flow.receive(102, body, now=1)
            self.assertEqual((flow.state, flow.error, queue.queued_frames), (SelectionState.FAILED, 'invalid_response', 0))
            self.assertNotIn('private', repr(flow))
        flow, queue = connection()
        flow.enter_list(now=0)
        queue.pop_frame()
        flow.receive(102, list_body(), now=1)
        flow.select(0, now=2)
        with self.assertRaises(ValueError): flow.receive(110, bytes(202), now=3)
        self.assertIsNone(flow.characters)

    def test_nonzero_result_requires_owner_attention_without_retry(self):
        flow, queue = connection()
        flow.enter_list(now=0)
        self.assertTrue(flow.receive(102, list_body(code=14), now=1))
        self.assertEqual((flow.error, flow.result_code, queue.queued_frames), ('unsupported_result_code', 14, 0))
        flow, queue = connection()
        flow.enter_list(now=0)
        queue.pop_frame()
        flow.receive(102, list_body(), now=1)
        flow.select(0, now=2)
        body = bytearray.fromhex(FIXTURE['select_result_hex'])
        struct.pack_into('<I', body, 0, 0x1197)
        flow.receive(110, bytes(body), now=3)
        self.assertEqual((flow.state, flow.result_code), (SelectionState.FAILED, 0x1197))
        self.assertIsNone(flow.response)

    def test_limits_clock_and_context_validation(self):
        for kwargs in (dict(max_payload_size=202), dict(max_characters=True), dict(max_collection_items=-1),
                       dict(request_timeout=0), dict(request_timeout=float('nan'))):
            with self.assertRaises(ValueError): connection(**kwargs)
        flow, queue = connection()
        for now in (True, -1, float('inf'), float('nan')):
            with self.assertRaises(ValueError): flow.enter_list(now=now)
        flow.enter_list(now=10)
        with self.assertRaises(ValueError): flow.expire(now=9)
        queue.pop_frame()
        flow.receive(102, list_body(), now=11)
        for value in (True, -1, 2**64):
            with self.assertRaises(ValueError): flow.update_raw_f0(value)


if __name__ == '__main__':
    unittest.main()
