"""Synthetic world transition and failure policies; no network or game actions."""
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.character_select_result import decode_character_select_result
from vampir_core.outbound import OutboundFrames
from vampir_core.selection_flow import SelectionState
from vampir_core.world_entry_flow import WorldEntryFlow
from vampir_core.world_move_start import SOURCE_SHA256
from vampir_core.world_reserve_context import decode_world_reserve_context


def reserve_body(code=0):
    return struct.pack('<IBQIBB', code, 255, 123, 456, 2, 255) + b'opaque-private-suffix'


def finish_body(code=0,vector=(1.5,-2.25,-0.0)):
    appearance=bytes(16)
    return (struct.pack('<IQIIBBfffBBB',code,123,1,2,0,0,*vector,45,0,0)
        +appearance+bytes(4)+struct.pack('<QHHH',0,0,0,0)+struct.pack('<QBB',0,0,0))


class WorldEntryFlowTests(unittest.TestCase):
    def setUp(self):
        fixture = json.loads((HERE / 'fixtures/vampir-selection-flow.json').read_text('utf-8'))
        response = decode_character_select_result(bytes.fromhex(fixture['select_result_hex']),
            max_payload_size=1048576, max_collection_items=4096)
        self.selection = SimpleNamespace(state=SelectionState.SELECT_RESPONSE, response=response)
        self.outbound = OutboundFrames(key_bits=0, sequence=10,
            max_queued_bytes=4096, max_queued_frames=4)
        self.flow = WorldEntryFlow(self.selection, self.outbound, source_sha256=SOURCE_SHA256,
            timeout=1, max_payload_size=4096)

    def test_prefix_clamps_preserve_opaque_suffix_and_hide_private_fields(self):
        value = decode_world_reserve_context(reserve_body(), max_payload_size=4096,
            source_sha256=SOURCE_SHA256)
        self.assertEqual((value.raw14, value.raw20, value.raw28, value.flag2c, value.raw2d),
            (32, 123, 456, True, 22))
        self.assertEqual(value.opaque_suffix, b'opaque-private-suffix')
        self.assertNotIn('private', repr(value))

    def test_prefix_requires_source_and_rejects_every_short_prefix_and_budget_overflow(self):
        for length in range(19):
            with self.assertRaises(ValueError):
                decode_world_reserve_context(reserve_body()[:length], max_payload_size=4096,
                    source_sha256=SOURCE_SHA256)
        with self.assertRaises(BufferError):
            decode_world_reserve_context(reserve_body(), max_payload_size=19,
                source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):
            decode_world_reserve_context(reserve_body(), max_payload_size=4096, source_sha256='old')

    def test_start_uses_fresh_selection_and_stops_before_world_completion(self):
        self.flow.receive(202, reserve_body(), now=0)
        self.assertEqual(self.flow.state, 'start_pending')
        self.assertEqual(self.outbound.sequence, 11)
        self.assertEqual(self.outbound.queued_frames, 1)
        self.flow.receive(204, struct.pack('<IIIIIBBQ', 0, 9, 1, 2, 3, 0, 0, 77), now=0.5)
        self.assertEqual(self.flow.state, 'start_response')
        self.assertEqual(self.flow.response.data.at(0x14), 9)
        self.assertEqual(self.outbound.queued_frames, 1)  # No ID205.
        self.flow.close()
        self.assertIsNone(self.flow.reserve)
        self.assertIsNone(self.flow.response)
        self.assertEqual((self.flow.reserve_result_code, self.flow.start_result_code), (0, 0))

    def test_reserve_refusal_keeps_public_code_after_close_without_start(self):
        self.flow.receive(202, reserve_body(16), now=0)
        self.assertEqual(self.flow.error, 'reserve_result_rejected')
        self.assertFalse(self.flow.request_sent)
        self.assertEqual(self.outbound.queued_frames, 0)
        self.flow.close()
        self.assertEqual(self.flow.reserve_result_code, 16)
        self.assertEqual(self.flow.error, 'reserve_result_rejected')

    def test_start_refusal_keeps_code_and_clears_queue(self):
        self.flow.receive(202, reserve_body(), now=0)
        self.flow.receive(204, struct.pack('<IIIIIBBQ', 16, 0, 0, 0, 0, 0, 0, 0), now=0.5)
        self.assertEqual(self.flow.error, 'start_result_rejected')
        self.assertEqual(self.outbound.queued_frames, 0)
        self.flow.close()
        self.assertEqual(self.flow.start_result_code, 16)

    def test_unsolicited_duplicate_and_malformed_responses_fail_closed(self):
        for kind in ('early', 'duplicate', 'short'):
            self.setUp()
            with self.assertRaises(ValueError):
                if kind == 'early':
                    self.selection.state = SelectionState.WAITING_ENTRY
                    self.flow.receive(202, reserve_body(), now=0)
                elif kind == 'duplicate':
                    self.flow.receive(202, reserve_body(), now=0)
                    self.flow.receive(202, reserve_body(), now=0)
                else:
                    self.flow.receive(202, b'private', now=0)
            self.assertEqual(self.flow.error, 'invalid_world_entry_response')
            self.assertEqual(self.outbound.queued_frames, 0)

    def test_timeout_waiting_for_each_response(self):
        self.flow.tick(0)
        self.flow.tick(1)
        self.assertEqual(self.flow.error, 'world_entry_timeout')
        self.setUp()
        self.flow.receive(202, reserve_body(), now=0)
        self.flow.tick(1)
        self.assertEqual(self.flow.error, 'world_entry_timeout')
        self.assertEqual(self.outbound.queued_frames, 0)

    def test_invalid_or_backwards_clock_and_invalid_budget(self):
        for now in (-1, float('nan'), float('inf'), True):
            with self.assertRaises(ValueError): self.flow.tick(now)
        self.flow.tick(1)
        with self.assertRaises(ValueError): self.flow.tick(0)
        for budget in (True, 29, 2**24):
            with self.assertRaises(ValueError):
                WorldEntryFlow(self.selection, self.outbound, source_sha256=SOURCE_SHA256,
                    timeout=1, max_payload_size=budget)


if __name__ == '__main__': unittest.main()
