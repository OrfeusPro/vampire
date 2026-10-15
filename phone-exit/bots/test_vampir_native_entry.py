import importlib.util
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('native_entry_code',
    Path(__file__).parent / 'resource-tools/vampir/build-native-entry-code.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def image_bytes():
    data = bytearray(0x800)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', data, 0x86, 4)
    struct.pack_into('<H', data, 0x94, 0xf0)
    optional = 0x98
    struct.pack_into('<H', data, optional, 0x20b)
    struct.pack_into('<Q', data, optional + 24, 0x140000000)
    struct.pack_into('<II', data, optional + 112 + 24, 0x2000, 24)
    for index, (name, rva, raw) in enumerate([
            (b'.text', 0x1000, 0x400), (b'.pdata', 0x2000, 0x500),
            (b'.xdata', 0x3000, 0x600), (b'.rdata', 0x4000, 0x700)]):
        offset = optional + 0xf0 + index * 40
        data[offset:offset + len(name)] = name
        struct.pack_into('<IIII', data, offset + 8, 0x100, rva, 0x100, raw)
    # LEA points to .rdata; RET is in a separately chained unwind fragment.
    data[0x400:0x408] = b'\x48\x8d\x15' + struct.pack('<i', 0x2ff9) + b'\xc3'
    struct.pack_into('<III', data, 0x500, 0x1000, 0x1007, 0x3000)
    struct.pack_into('<III', data, 0x50c, 0x1007, 0x1008, 0x3010)
    data[0x600] = 1
    data[0x610] = 33  # UNW_FLAG_CHAININFO | version 1
    struct.pack_into('<III', data, 0x614, 0x1000, 0x1007, 0x3000)
    return data


class NativeEntryEvidence(unittest.TestCase):
    def test_unwind_chain_unites_fragments_without_guessing_adjacency(self):
        image = module.Image(image_bytes())
        child = image.ranges[1]
        self.assertEqual(image.roots[child], image.ranges[0])
        self.assertEqual(image.containing(0x140001007), child)
        self.assertIsNone(image.containing(0x140001008))
        fragments = module.decode_ranges(image, {image.ranges[0]})
        self.assertEqual(len(fragments), 2)
        self.assertEqual(fragments[1]['instructions'][0]['mnemonic'], 'ret')

    def test_rip_reference_verified_against_decoded_operand(self):
        image = module.Image(image_bytes())
        self.assertEqual(module.rip_candidates(image, {0x140004000}), [(0x140001000, 0x140004000)])
        instruction = module.decode_ranges(image, {image.ranges[0]})[0]['instructions'][0]
        self.assertEqual(instruction['rip_references'], [0x140004000])

    def test_unwind_cycle_rejected(self):
        data = image_bytes()
        struct.pack_into('<III', data, 0x614, 0x1007, 0x1008, 0x3010)
        with self.assertRaisesRegex(ValueError, 'chain'):
            module.Image(data)

    def test_overlapping_ranges_rejected(self):
        data = image_bytes()
        struct.pack_into('<I', data, 0x50c, 0x1006)
        with self.assertRaisesRegex(ValueError, 'Overlapping'):
            module.Image(data)

    def test_invalid_exception_directory_rejected(self):
        data = image_bytes()
        struct.pack_into('<I', data, 0x98 + 112 + 24 + 4, 25)
        with self.assertRaisesRegex(ValueError, 'directory'):
            module.Image(data)

    def test_unmapped_unwind_rejected(self):
        data = image_bytes()
        struct.pack_into('<I', data, 0x508, 0x99000)
        with self.assertRaisesRegex(ValueError, 'RVA'):
            module.Image(data)

    def test_incomplete_instruction_rejected(self):
        data = image_bytes()
        struct.pack_into('<I', data, 0x504, 0x1006)
        with self.assertRaisesRegex(ValueError, 'fully decoded'):
            module.decode_ranges(module.Image(data), {(0x1000, 0x1006, 0x3000)})


if __name__ == '__main__':
    unittest.main()
