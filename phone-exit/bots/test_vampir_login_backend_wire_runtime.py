"""Pure shared-heap, publisher-provider and sender-stack boundary regressions."""
import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

TOOLS = Path(__file__).resolve().parent / 'resource-tools' / 'vampir'
spec = importlib.util.spec_from_file_location('backend_runtime', TOOLS / 'login-backend-wire-runtime.py')
RUNTIME = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RUNTIME)


class CheckedMemory:
    def __init__(self):
        self.data = {}
        self.retired = []

    def mem_write(self, address, data):
        if any(address < end and address + len(data) > start for start, end in self.retired):
            raise ValueError('retired write')
        self.data.update({address + i: byte for i, byte in enumerate(data)})

    def mem_read(self, address, size):
        if any(address < end and address + size > start for start, end in self.retired):
            raise ValueError('retired read')
        return bytes(self.data.get(address + i, 0) for i in range(size))

    def retire(self, address, size):
        self.retired.append((address, address + size))


class AllocationLedgerTests(unittest.TestCase):
    def setUp(self):
        self.h = SimpleNamespace(scratch=0x28000000, uc=CheckedMemory())
        self.state = dict(heap=self.h.scratch + 0x50000, allocations={}, allocation_records={},
            allocation_owners={}, freed=set(), fixture_owner='wire.archive.raw',
            fixture_callsite=0x123456, phase='delivery')
        self.ledger = RUNTIME.AllocationLedger(self.h, self.state)

    def test_one_heap_keeps_distinct_owner_kind_and_native_provenance(self):
        utf16 = self.ledger.allocate(18)
        archive = self.ledger.allocate(1024, 'archive', 'inner')
        utf8 = self.ledger.allocate(260, 'utf8')
        self.assertTrue(utf16 < archive < utf8)
        self.assertEqual(self.state['allocations'][archive], 1024)
        record = self.state['allocation_records'][archive]
        self.assertEqual((record['kind'], record['owner'], record['created_by_source_caller'], record['phase']),
                         ('archive', 'inner', 0x123456, 'delivery'))
        extents = sorted((at - 16, at + size + 16) for at, size in self.state['allocations'].items())
        self.assertTrue(all(end <= next_start for (_, end), (next_start, _) in zip(extents, extents[1:])))
        self.assertGreaterEqual(extents[0][0], self.h.scratch + 0x50000)
        self.assertLess(extents[-1][1], self.h.scratch + 0x100000)

    def test_shared_free_cannot_release_wrong_codec_or_provider_kind(self):
        at = self.ledger.allocate(30, 'utf8')
        with self.assertRaisesRegex(ValueError, 'kind'):
            self.ledger.release(at, 'utf16')
        self.assertNotIn(at, self.state['freed'])
        self.ledger.release(at, 'utf8')
        self.assertTrue(self.state['allocation_records'][at]['retired'])
        with self.assertRaisesRegex(ValueError, 'repeated'):
            self.ledger.release(at, 'utf8')
        for operation in (lambda: self.h.uc.mem_read(at, 1), lambda: self.h.uc.mem_write(at, b'X')):
            with self.assertRaises(ValueError):
                operation()

    def test_sized_delete_checks_exact_size_and_preserves_failure_ownership(self):
        at = self.ledger.allocate(1024, 'archive')
        for wrong in (1023, 2048, True, 1024.0):
            with self.assertRaisesRegex(ValueError, 'sized'):
                self.ledger.release(at, 'archive', wrong)
        self.assertNotIn(at, self.state['freed'])
        self.ledger.release(at, 'archive', 1024)
        self.assertEqual(self.state['allocation_records'][at]['free_caller'], 0x123456)

    def test_guards_detect_overflow_before_retirement(self):
        at = self.ledger.allocate(20, 'cpp')
        self.h.uc.mem_write(at + 20, b'!')
        with self.assertRaisesRegex(ValueError, 'canary'):
            self.ledger.release(at, 'cpp', 20)
        self.assertNotIn(at, self.state['freed'])

    def test_heap_bound_type_and_foreign_free_are_rejected(self):
        for size in (0, -1, True, 1.0, 8193):
            with self.assertRaises(ValueError):
                self.ledger.allocate(size)
        with self.assertRaises(ValueError):
            self.ledger.allocate(1, 'untyped')
        self.state['heap'] = self.h.scratch + 0x100000 - 32
        with self.assertRaises(ValueError):
            self.ledger.allocate(1)
        with self.assertRaisesRegex(ValueError, 'foreign'):
            self.ledger.release(0x1234)


class PublisherProviderTests(unittest.TestCase):
    def test_native_final_fields_preserve_holes_and_zero_backend(self):
        result = RUNTIME.publisher_expected(0x55, 0x2000, 0x3000)
        self.assertEqual(len(result), 240)
        self.assertEqual(struct.unpack_from('<QQQ', result), (0x2000, 0x3000, 0))
        self.assertEqual(result[0x20:0x28], b'\x55' * 8)
        self.assertEqual(result[0x38:0x48], b'\x55' * 16)
        self.assertEqual(result[0xf0 - 8:0xf0], bytes(8))
        self.assertEqual(struct.unpack_from('<IIII', result, 0x50), (0, 128, 0xffffffff, 0))
        self.assertEqual(struct.unpack_from('<IIII', result, 0xb0), (0, 128, 0xffffffff, 0))

    def test_provider_cannot_claim_service_forwarded_before_source_observation(self):
        pending = dict(forwarded=True, timeout_bits=0x3fa00000)
        actual = RUNTIME.handoff_state({'pending_case': 'empty-count-equal'}, pending)
        self.assertEqual(actual['service_calls'], 0)
        self.assertIsNone(actual['service_same_packet'])
        self.assertIsNone(actual['thunk_arguments_checked'])
        self.assertNotIn('synthetic_service_vtable', actual)
        self.assertNotIn('sink_calls', actual)


class SenderProviderTests(unittest.TestCase):
    def test_heap_chain_is_hash_consistent_and_distinguishes_pending_id(self):
        session, nodes, buckets = 0x1000, 0x2000, 0x3000
        body, raw_nodes, raw_buckets = RUNTIME.pending_layout('heap-chain-hit', nodes, buckets, 0x40900000)
        self.assertEqual(struct.unpack_from('<Q', body, 0x38)[0], nodes)
        self.assertEqual(struct.unpack_from('<Q', body, 0x78)[0], buckets)
        capacity = struct.unpack_from('<I', body, 0x80)[0]
        index = struct.unpack_from('<i', raw_buckets, (4 & (capacity - 1)) * 4)[0]
        chain = []
        while index != -1:
            key = struct.unpack_from('<h', raw_nodes, index * 32)[0]
            chain.append(key)
            self.assertEqual(key & (capacity - 1), 4 & (capacity - 1))
            index = struct.unpack_from('<i', raw_nodes, index * 32 + 0x18)[0]
        self.assertEqual(chain, [8, 4])
        self.assertNotIn(3, chain)

    def test_pending_aliases_cannot_replace_record_with_equal_bytes_elsewhere(self):
        s = 0x3000
        RUNTIME.check_pending_aliases(s, s + 0x58, s + 0x38, s + 0x68, s + 0x28)
        with self.assertRaises(ValueError):
            RUNTIME.check_pending_aliases(s, s + 0x58, s + 0x38, s + 0x68, s + 0x128)


class SharedFixtureTests(unittest.TestCase):
    def test_native_caller_selects_shared_free_and_cookie_abi(self):
        parent_free, codec_free = object(), object()
        parent_cookie, codec_cookie = object(), object()
        parent = {0x1000: parent_free, 0x2000: parent_cookie}
        codec = {0x1000: codec_free, 0x2000: codec_cookie}
        for address, parent_callback, codec_callback in (
                (0x1000, parent_free, codec_free), (0x2000, parent_cookie, codec_cookie)):
            for role in ('prepare', 'metadata.collector', 'sdk.sdk_mode'):
                self.assertEqual(RUNTIME.fixture_for_owner(address, role, parent, codec),
                                 (parent_callback, False))
            self.assertEqual(RUNTIME.fixture_for_owner(address, 'wire.string-writer', parent, codec),
                             (codec_callback, True))

    def test_unknown_wire_callback_cannot_fall_back_to_parent_hook(self):
        with self.assertRaises(ValueError):
            RUNTIME.fixture_for_owner(0x1000, 'wire.cleanup', {0x1000: object()}, {})
        with self.assertRaises(ValueError):
            RUNTIME.fixture_for_owner(0x1000, 'metadata.collector', {}, {0x1000: object()})

    def test_backend_checksum_routes_codec_while_state_provider_stays_runtime(self):
        checksum, state = object(), object()
        parent = {0x2000: state}
        codec = {0x1000: checksum}
        self.assertEqual(RUNTIME.fixture_for_owner(0x1000, 'backend', parent, codec), (checksum, True))
        self.assertEqual(RUNTIME.fixture_for_owner(0x2000, 'backend', parent, codec), (state, False))


if __name__ == '__main__':
    unittest.main()
