"""Adversarial fixture/policy tests; never execute source/native instructions."""
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
TOOLS = HERE / 'resource-tools' / 'vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), TOOLS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MEMORY, HARNESS = load('buffer-transport-memory'), load('buffer-transport-harness')


class FakeMemory:
    def __init__(self):
        self.data, self.reads, self.writes = {}, [], []

    def mem_read(self, address, size):
        self.reads.append((address, size))
        return bytes(self.data.get(address + i, 0) for i in range(size))

    def mem_write(self, address, data):
        self.writes.append((address, bytes(data)))
        self.data.update({address + i: value for i, value in enumerate(data)})


class BufferFixtureTests(unittest.TestCase):
    def setUp(self):
        self.raw = FakeMemory()
        self.memory = MEMORY.MemoryPolicy(self.raw)
        self.ledger = MEMORY.AllocationLedger(self.memory, 0x1000, 0x30000)

    def test_memcpy_rejects_overlap_before_writing(self):
        self.memory.mem_write(100, b'abcdef')
        before = list(self.raw.writes)
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            MEMORY.copy_memory(self.memory, 101, 100, 4)
        self.assertEqual(self.raw.writes, before)

    def test_memmove_snapshots_overlapping_source(self):
        self.memory.mem_write(100, b'abcdef')
        self.memory.native_read_allow([(100, 6)])
        self.assertEqual(MEMORY.copy_memory(self.memory, 101, 100, 5, move=True), 101)
        self.assertEqual(self.memory.mem_read(100, 6), b'aabcde')

    def test_zero_memory_import_never_dereferences_retired_pointer(self):
        self.memory.retire(100, 8)
        reads, writes = len(self.raw.reads), len(self.raw.writes)
        self.assertEqual(MEMORY.copy_memory(self.memory, 100, 100, 0), 100)
        self.assertEqual(MEMORY.fill_memory(self.memory, 100, 0, 0), 100)
        self.assertEqual((len(self.raw.reads), len(self.raw.writes)), (reads, writes))

    def test_free_rejects_wrong_size_then_double_free_and_stale_copy(self):
        pointer = self.ledger.allocate(32, owner='vector')
        with self.assertRaisesRegex(ValueError, 'wrong-sized'):
            self.ledger.release(pointer, 31)
        self.ledger.release(pointer, 32)
        with self.assertRaisesRegex(ValueError, 'repeated'):
            self.ledger.release(pointer, 32)
        with self.assertRaisesRegex(ValueError, 'retired'):
            MEMORY.copy_memory(self.memory, 0x800, pointer, 1)

    def test_native_writes_cannot_hit_guards_or_retired_payload(self):
        pointer = self.ledger.allocate(32, owner='vector')
        self.memory.writable(pointer, 32, native=True)
        with self.assertRaisesRegex(ValueError, 'declared windows'):
            self.memory.writable(pointer - 1, 1, native=True)
        self.ledger.release(pointer, 32)
        with self.assertRaisesRegex(ValueError, 'retired'):
            self.memory.writable(pointer, 1, native=True)

    def test_provider_guard_detects_corruption(self):
        pointer = self.ledger.allocate(32, owner='vector', fixture=True)
        self.raw.mem_write(pointer + 32, b'X')
        with self.assertRaisesRegex(ValueError, 'guard changed'):
            self.ledger.check_guards()

    def test_scoped_fixture_cannot_modify_foreign_memory(self):
        self.memory.begin_fixture([(100, 4)])
        try:
            with self.assertRaisesRegex(ValueError, 'fixture write outside'):
                self.memory.mem_write(104, b'X')
            with self.assertRaisesRegex(ValueError, 'Nested'):
                self.memory.begin_fixture([(100, 4)])
        finally:
            self.memory.end_fixture()

    def test_immutable_frame_cannot_be_a_copy_destination(self):
        self.memory.protect([(100, 8)])
        with self.assertRaisesRegex(ValueError, 'immutable'):
            MEMORY.fill_memory(self.memory, 100, 0, 1)

    def test_aligned_raw_block_can_hold_native_header_and_payload(self):
        raw = self.ledger.allocate(4096 + 39, owner='vector')
        pointer = (raw + 39) & ~31
        self.assertEqual(pointer & 31, 0)
        self.assertNotEqual(raw & 31, 0)
        self.memory.writable(pointer - 8, 8, native=True)
        self.ledger.containing(pointer, 4096)
        self.assertLessEqual(pointer - raw - 8, 31)

    def test_native_read_cannot_cross_descriptor_boundary(self):
        self.memory.native_read_allow([(100, 24)])
        self.memory.readable(100, 24, native=True)
        with self.assertRaisesRegex(ValueError, 'read outside'):
            self.memory.readable(116, 16, native=True)
        with self.assertRaisesRegex(ValueError, 'read outside'):
            self.memory.readable(0xdead0000, 1, native=True)
        # Host guard inspection remains available outside native read windows.
        self.assertEqual(self.memory.mem_read(124, 1), b'\0')

    def test_native_read_cannot_cross_raw_block_guard(self):
        pointer = self.ledger.allocate(8, owner='vector')
        self.memory.readable(pointer, 8, native=True)
        with self.assertRaisesRegex(ValueError, 'read outside'):
            self.memory.readable(pointer + 7, 2, native=True)
        with self.assertRaisesRegex(ValueError, 'read outside'):
            self.memory.readable(pointer - 1, 1, native=True)
        self.assertEqual(self.memory.mem_read(pointer - 1, 1), b'\xa5')

    def test_native_input_read_uses_exact_payload_not_offset_padding(self):
        pointer = self.ledger.allocate(8, owner='input')
        self.ledger.input_read_span(pointer, 3, 4)
        self.memory.readable(pointer + 3, 4, native=True)
        for address, size in ((pointer + 2, 1), (pointer + 6, 2)):
            with self.assertRaisesRegex(ValueError, 'read outside'):
                self.memory.readable(address, size, native=True)
        self.ledger.release(pointer, 8)
        self.assertEqual(self.memory.native_read_windows, [])
        with self.assertRaisesRegex(ValueError, 'retired'):
            self.memory.readable(pointer + 3, 1, native=True)

    def test_free_preserves_only_other_live_read_windows(self):
        first = self.ledger.allocate(8, owner='vector')
        second = self.ledger.allocate(16, owner='vector')
        self.ledger.release(first, 8)
        self.memory.readable(second, 16, native=True)
        with self.assertRaisesRegex(ValueError, 'retired'):
            self.memory.readable(first, 1, native=True)
        self.assertEqual(self.memory.native_read_windows, [(second, second + 16)])

    def aligned_vector(self, raw_extra=39):
        raw = self.ledger.allocate(4096 + raw_extra, owner='vector')
        pointer = (raw + 39) & ~31
        self.memory.mem_write(pointer - 8, raw.to_bytes(8, 'little'))
        return raw, pointer

    def test_retained_aligned_vector_checks_actual_header(self):
        raw, pointer = self.aligned_vector()
        self.assertEqual(self.ledger.check_vector(pointer, pointer + 4, pointer + 4096), raw)
        self.memory.mem_write(pointer - 8, (raw + 1).to_bytes(8, 'little'))
        with self.assertRaisesRegex(ValueError, 'raw-pointer header'):
            self.ledger.check_vector(pointer, pointer + 4, pointer + 4096)

    def test_retained_aligned_vector_rejects_misalignment(self):
        raw, pointer = self.aligned_vector()
        with self.assertRaisesRegex(ValueError, 'aligned vector geometry'):
            self.ledger.check_vector(pointer + 1, pointer + 5, pointer + 4097)

    def test_retained_aligned_vector_rejects_wrong_raw_size(self):
        raw, pointer = self.aligned_vector(raw_extra=40)
        with self.assertRaisesRegex(ValueError, 'raw size'):
            self.ledger.check_vector(pointer, pointer + 4, pointer + 4096)

    def test_retained_small_vector_requires_exact_raw_pointer_and_size(self):
        pointer = self.ledger.allocate(8, owner='vector')
        self.assertEqual(self.ledger.check_vector(pointer, pointer + 4, pointer + 8), pointer)
        for begin, end, limit in ((pointer + 1, pointer + 4, pointer + 8),
                                  (pointer, pointer + 4, pointer + 7)):
            with self.assertRaisesRegex(ValueError, 'small vector pointer/raw size'):
                self.ledger.check_vector(begin, end, limit)

    def test_entry_gate_forbids_hidden_helpers_and_unfinished_reuse(self):
        functions = dict(zip(HARNESS.ROLES, range(100, 105)))
        gate = HARNESS.EntrySequence(functions)
        spec = dict(mode='append', steps=[{}, {}])
        gate.begin_case(spec)
        with self.assertRaisesRegex(ValueError, 'Undeclared'):
            gate.enter(functions['vector.grow'])
        gate.enter(functions['queue.append'])
        with self.assertRaisesRegex(ValueError, 'nested'):
            gate.enter(functions['queue.append'])
        gate.finish(True)
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            gate.begin_case(spec)
        gate.enter(functions['queue.append'])
        gate.finish(True)
        self.assertEqual(gate.phase, 'complete')
        self.assertEqual(gate.history, [functions['queue.append']] * 2)

    def test_provider_cannot_shadow_inside_native_leaf(self):
        with self.assertRaisesRegex(ValueError, 'shadows'):
            HARNESS.check_fixture_address(0x101, [(0x100, 0x104)])
        HARNESS.check_fixture_address(0x104, [(0x100, 0x104)])


if __name__ == '__main__':
    unittest.main()
