import importlib.util
import struct
import unittest
from pathlib import Path

PATH = Path(__file__).parent / 'resource-tools/vampir/decode-message-named-slot.py'
SPEC = importlib.util.spec_from_file_location('message_named_slot_test', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NamedSlotPrefixTests(unittest.TestCase):
    def raw(self, count=1, name=0, number=0, content=17, slot=6, tail=b'\0\0\0\0'):
        return (bytes.fromhex('3b020803') + struct.pack('<i', count) + bytes.fromhex('0005') +
                struct.pack('<iiii', name, number, content, slot) + tail)

    def test_observed_prefix_preserves_unproven_schema_and_opaque_tail(self):
        result = MODULE.decode_observed_prefix(self.raw(tail=b'\xff\0\0\0'), ['NamedSlotContent'])
        self.assertEqual(result['observed_bindings'][0]['content_export'], 17)
        self.assertEqual(result['observed_slot_reference'], 6)
        self.assertEqual(result['opaque_tail'], 'ff000000')
        self.assertFalse(result['class_property_ordinal_verified'])
        self.assertFalse(result['whole_export_decoded'])

    def test_unknown_instance_or_struct_header_is_rejected(self):
        for position in (0, 8):
            raw = bytearray(self.raw())
            raw[position] ^= 1
            with self.subTest(position=position), self.assertRaises(ValueError):
                MODULE.decode_observed_prefix(bytes(raw), ['NamedSlotContent'])

    def test_invalid_fname_and_nonlocal_content_are_rejected(self):
        for changes in [dict(name=-1), dict(name=1), dict(number=1), dict(content=0), dict(content=-3), dict(slot=0)]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                MODULE.decode_observed_prefix(self.raw(**changes), ['NamedSlotContent'])

    def test_array_bounds_and_truncation_are_rejected(self):
        for raw in [self.raw(count=-1), self.raw(count=65), self.raw()[:18], self.raw()[:25]]:
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                MODULE.decode_observed_prefix(raw, ['NamedSlotContent'])


if __name__ == '__main__':
    unittest.main()
