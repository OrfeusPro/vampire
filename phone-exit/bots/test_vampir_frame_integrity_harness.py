"""Fixture-only checks for exact entry modes and immutable memory boundaries."""
import importlib.util
from pathlib import Path
import unittest

TOOLS = Path(__file__).resolve().parent / 'resource-tools/vampir'
def load(name):
    s = importlib.util.spec_from_file_location(name.replace('-', '_'), TOOLS / (name + '.py'))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
H = load('frame-integrity-harness')
C = load('frame-integrity-case-contracts')


class EntryModeTests(unittest.TestCase):
    def setUp(self): self.gate = H.EntrySequence(0x1000, 0x2000, 0x3000, 0x4000)

    def test_backend_allows_only_one_top_entry(self):
        self.gate.begin_case(C.integration_specs()[0])
        for helper in (0x2000, 0x3000, 0x4000, 0x1001):
            with self.assertRaises(ValueError): self.gate.enter(helper)
        self.gate.enter(0x1000)
        with self.assertRaisesRegex(ValueError, 'Nested'): self.gate.enter(0x3000)
        self.gate.finish(True)
        self.assertEqual(self.gate.history, [0x1000])
        with self.assertRaises(ValueError): self.gate.enter(0x1000)

    def test_incremental_crc_uses_only_declared_init_and_update_entries(self):
        spec = next(s for s in C.primitive_specs() if s['group'] == 'incremental')
        self.gate.begin_case(spec)
        with self.assertRaises(ValueError): self.gate.enter(0x3000)
        self.gate.enter(0x2000); self.gate.finish(True)
        for _ in spec['chunks']:
            self.gate.enter(0x3000); self.gate.finish(True)
        self.assertEqual(self.gate.phase, 'complete')
        self.assertEqual(self.gate.history, [0x2000] + [0x3000] * len(spec['chunks']))
        with self.assertRaises(ValueError): self.gate.enter(0x3000)

    def test_raw_crc_does_not_allow_unrequested_initializer(self):
        spec = next(s for s in C.primitive_specs() if s['group'] == 'raw-seed')
        self.gate.begin_case(spec)
        with self.assertRaises(ValueError): self.gate.enter(0x2000)
        self.gate.enter(0x3000); self.gate.finish(True)

    def test_failed_case_cannot_silently_restart(self):
        self.gate.begin_case(C.primitive_specs()[0]); self.gate.enter(0x2000); self.gate.finish(False)
        with self.assertRaises(ValueError): self.gate.begin_case(C.integration_specs()[0])
        with self.assertRaises(ValueError): self.gate.enter(0x1000)

    def test_fixture_cannot_shadow_native_leaf_or_middle_of_instruction(self):
        spans = [(0x2000, 0x200a), (0x3000, 0x3037), (0x4000, 0x4054)]
        for at in (0x2000, 0x2009, 0x3023, 0x4053):
            with self.assertRaises(ValueError): H.check_fixture_address(at, spans)
        H.check_fixture_address(0x4054, spans)


class MemoryPolicyTests(unittest.TestCase):
    def test_native_reads_cannot_cross_primitive_payload_state_or_table_bounds(self):
        p = H.MemoryPolicy(object())
        p.native_read_allow([(0x1001, 9), (0x2003, 4), (0x3000, 1024)])
        p.readable(0x1001, 9, native=True)
        p.readable(0x2003, 4, native=True)
        p.readable(0x33fc, 4, native=True)
        for at, size in ((0x1000, 1), (0x1009, 2), (0x2003, 8), (0x33fd, 4)):
            with self.assertRaises(ValueError): p.readable(at, size, native=True)
        # Host inspection can read canaries without granting native access.
        p.readable(0x1000, 16)
        p.reset(); self.assertIsNone(p.native_read_windows)

    def test_xor_may_change_only_payload_and_native_home_slot(self):
        p = H.MemoryPolicy(object())
        p.native_allow([(0x1000, 1024), (0x3000, 0x100)])
        p.protect([(0x1000, 3), (0x1080, 1024 - 128)])
        p.writable(0x1003, 125, native=True)
        p.writable(0x3020, 8, native=True)
        for at, size in ((0x1002, 2), (0x107f, 2), (0x1400, 1)):
            with self.assertRaises(ValueError): p.writable(at, size, native=True)

    def test_retired_archive_is_not_readable_even_in_broad_heap_window(self):
        p = H.MemoryPolicy(object()); p.native_allow([(0x1000, 4096)]); p.retire(0x1100, 1024)
        with self.assertRaises(ValueError): p.readable(0x1100, 1)
        with self.assertRaises(ValueError): p.writable(0x1200, 1, native=True)
        p.readable(0x1500, 16)


if __name__ == '__main__': unittest.main()
