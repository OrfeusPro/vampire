import importlib.util
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('native_enums', Path(__file__).parent / 'resource-tools/vampir/extract-native-enums.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(two_arrays=False):
    data = bytearray(2048)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', data, 0x86, 1)
    struct.pack_into('<H', data, 0x94, 0xf0)
    struct.pack_into('<H', data, 0x98, 0x20b)
    struct.pack_into('<Q', data, 0xb0, 0x140000000)
    data[0x188:0x190] = b'.rdata\0\0'
    struct.pack_into('<IIII', data, 0x190, 0x600, 0x1000, 0x600, 0x200)
    for offset, name in [(0x240, b'ETest::First\0'), (0x270, b'ETest::Later\0')]:
        data[offset:offset + len(name)] = name
    for start in ([0x300, 0x350] if two_arrays else [0x300]):
        struct.pack_into('<QqQq', data, start, 0x140001040, 2, 0x140001070, 100)
    return data


class NativeEnums(unittest.TestCase):
    def test_unqualified_alignment_family_keeps_native_names(self):
        data = fixture()
        data[0x240:0x260] = b'\0' * 32
        data[0x270:0x290] = b'\0' * 32
        for offset, name in [(0x240, b'HAlign_Fill\0'), (0x270, b'HAlign_Right\0')]:
            data[offset:offset + len(name)] = name
        rows = module.extract(data)[0]['unqualified:HAlign']
        self.assertEqual([(r['name'], r['value']) for r in rows], [('HAlign_Fill', 2), ('HAlign_Right', 100)])

    def test_values_come_from_descriptors_including_gaps(self):
        result, rejected = module.extract(fixture())
        self.assertEqual([r['value'] for r in result['ETest']], [2, 100])
        self.assertEqual(result['ETest'][1]['descriptor_offset'], 0x310)
        self.assertEqual(rejected, [])

    def test_ambiguous_arrays_are_rejected(self):
        result, rejected = module.extract(fixture(True))
        self.assertNotIn('ETest', result)
        self.assertEqual(rejected[0]['candidates'], 2)

    def test_unmapped_name_pointer_is_not_accepted(self):
        data = fixture()
        struct.pack_into('<Q', data, 0x310, 0x777777777777)
        self.assertEqual(module.extract(data)[0], {})

    def test_invalid_section_range_is_rejected(self):
        data = fixture()
        struct.pack_into('<I', data, 0x190 + 12, 0x10000)
        with self.assertRaises(ValueError):
            module.extract(data)
