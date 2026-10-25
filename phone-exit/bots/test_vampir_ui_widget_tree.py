"""Explicit source roots, omission and unreviewed WidgetTree payload boundaries."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'resource-tools/vampir'))
from ui_widget_tree import decode_root


class RootTests(unittest.TestCase):
    def test_explicit_local_external_and_null_references(self):
        for value in [1, 27, 0, -5]:
            with self.subTest(value=value):
                result = decode_root(struct.pack('<HiI', 0x300, value, 0))
                self.assertEqual(result['explicit_root_widget'], value)
                self.assertFalse(result['root_omitted'])

    def test_omission_is_not_default(self):
        result = decode_root(struct.pack('<HI', 0x100, 0))
        self.assertIsNone(result['explicit_root_widget'])
        self.assertTrue(result['root_omitted'])

    def test_serialized_zero_reference_is_explicit(self):
        result = decode_root(struct.pack('<HB', 0x380, 1) + struct.pack('<I', 0))
        self.assertEqual(result['explicit_root_widget'], 0)
        self.assertFalse(result['root_omitted'])

    def test_unreviewed_properties_and_bad_suffix_rejected(self):
        for raw in [struct.pack('<HiI', 0x301, 2, 0), struct.pack('<HiI', 0x300, 1, 9),
                    struct.pack('<HiI', 0x300, 1, 0) + b'\0', b'\0']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                decode_root(raw)


if __name__ == '__main__':
    unittest.main()
