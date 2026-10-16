"""Reject switch evidence that points into data or lacks a full type table."""
import importlib.util
import struct
import unittest
from pathlib import Path

PATH = Path(__file__).parent / 'resource-tools/vampir/build-lock-predicate-code.py'
SPEC = importlib.util.spec_from_file_location('vampir_predicate_code', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PredicateEvidenceTests(unittest.TestCase):
    def test_shared_default_is_valid_when_it_is_code(self):
        raw = struct.pack('<11I', *([0x1000, 0x1010] + [0x1020] * 9))
        result = MODULE.checked_switch(raw, 0x140000000,
                                       {0x140001000, 0x140001010, 0x140001020})
        self.assertEqual(result[0], 0x140001000)
        self.assertEqual(result.count(0x140001020), 9)

    def test_target_inside_an_instruction_is_rejected(self):
        raw = struct.pack('<11I', *([0x1000] * 10 + [0x1001]))
        with self.assertRaisesRegex(ValueError, 'boundaries'):
            MODULE.checked_switch(raw, 0x140000000, {0x140001000})

    def test_short_and_extra_tables_are_rejected(self):
        for count in (0, 10, 12):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, 'eleven'):
                MODULE.checked_switch(struct.pack('<' + str(count) + 'I', *([0x1000] * count)),
                                      0x140000000, {0x140001000})


if __name__ == '__main__':
    unittest.main()
