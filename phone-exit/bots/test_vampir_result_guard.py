"""Malformed compact dispatch must not silently become evidence about outcomes."""
import importlib.util
import struct
import unittest
from pathlib import Path

PATH = Path(__file__).parent / 'resource-tools/vampir/build-packet-result-guard.py'
SPEC = importlib.util.spec_from_file_location('vampir_result_guard', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CompactResultDispatchTests(unittest.TestCase):
    def setUp(self):
        self.base = 0x140000000
        self.targets = struct.pack('<4I', 0x1000, 0x1010, 0x1020, 0x1000)
        self.boundaries = {self.base + n for n in (0x1000, 0x1010, 0x1020)}

    def test_two_stage_dispatch_preserves_result_index_and_shared_targets(self):
        selectors = bytes([0, 1, 2, 3] + [3] * 223)
        rows = MODULE.checked_compact_dispatch(self.targets, selectors, self.base, self.boundaries)
        self.assertEqual(len(rows), 227)
        self.assertEqual(rows[2], dict(result=0x51b, selector=2, target=self.base + 0x1020))
        self.assertEqual(rows[-1]['result'], 0x5fb)
        self.assertEqual(rows[0]['target'], rows[3]['target'])

    def test_out_of_bounds_selector_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Selector'):
            MODULE.checked_compact_dispatch(self.targets, bytes([3] * 226 + [4]), self.base, self.boundaries)

    def test_non_instruction_target_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'boundary'):
            MODULE.checked_compact_dispatch(struct.pack('<4I', 0x1000, 0x1001, 0x1020, 0x1000),
                                             bytes([0] * 227), self.base, self.boundaries)

    def test_truncated_or_extra_table_bytes_are_rejected(self):
        for target_size, selector_size in [(15, 227), (17, 227), (16, 226), (16, 228)]:
            with self.subTest(target_size=target_size, selector_size=selector_size), self.assertRaisesRegex(ValueError, 'size'):
                MODULE.checked_compact_dispatch(bytes(target_size), bytes(selector_size), self.base, self.boundaries)


if __name__ == '__main__':
    unittest.main()
