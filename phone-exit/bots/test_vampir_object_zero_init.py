import importlib.util
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('zero_init_test', Path(__file__).parent / 'resource-tools/vampir/build-object-zero-init-code.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ObjectZeroInitTests(unittest.TestCase):
    def fixture(self):
        data = bytearray(4096)
        struct.pack_into('<I', data, 60, 0x40)
        struct.pack_into('<II', data, 0x40 + 24 + 112 + 8, 0x200, 40)
        struct.pack_into('<IIIII', data, 0x200, 0x300, 0, 0, 0x400, 0x500)
        struct.pack_into('<Q', data, 0x300, 0x600)
        data[0x400:0x411] = b'VCRUNTIME140.dll\0'
        data[0x602:0x609] = b'memset\0'

        def offset(rva):
            if not 0 <= rva < len(data):
                raise ValueError('Outside fixture image')
            return rva
        return data, SimpleNamespace(pe=SimpleNamespace(base=0x140000000), offset=offset)

    def test_named_import_resolved_from_thunk_not_neighbor_name(self):
        data, image = self.fixture()
        row = module.import_at(data, image, image.pe.base + 0x500)
        self.assertEqual((row['dll'], row['name']), ('VCRUNTIME140.dll', 'memset'))
        self.assertEqual(row['thunk_offset'], 0x300)
        self.assertEqual(bytes.fromhex(row['name_bytes']), b'memset\0')

    def test_unaligned_target_and_target_after_terminator_rejected(self):
        for address in [0x501, 0x508, 0x510]:
            data, image = self.fixture()
            with self.assertRaises(ValueError):
                module.import_at(data, image, image.pe.base + address)

    def test_ordinal_and_missing_import_name_rejected(self):
        data, image = self.fixture()
        struct.pack_into('<Q', data, 0x300, (1 << 63) | 9)
        with self.assertRaisesRegex(ValueError, 'Ordinal'):
            module.import_at(data, image, image.pe.base + 0x500)
        data, image = self.fixture()
        data[0x602:0xa02] = b'x' * 1024
        with self.assertRaisesRegex(ValueError, 'Unterminated'):
            module.import_at(data, image, image.pe.base + 0x500)

    def test_invalid_directory_rejected(self):
        data, image = self.fixture()
        struct.pack_into('<I', data, 0x40 + 24 + 112 + 12, 0)
        with self.assertRaisesRegex(ValueError, 'directory'):
            module.import_at(data, image, image.pe.base + 0x500)


if __name__ == '__main__':
    unittest.main()
