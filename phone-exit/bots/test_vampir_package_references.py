import importlib.util
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('package_refs', Path(__file__).parent / 'resource-tools/vampir/decode-package-references.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PackageReferenceTests(unittest.TestCase):
    def fixture(self):
        a = bytearray(512)
        package = b'/Game/Lift\0'
        struct.pack_into('<i', a, 32, len(package))
        a[36:36 + len(package)] = package
        struct.pack_into('<iiii', a, 36 + len(package) + 28, 2, 256, 2, 160)
        # Import package and its named object; package paths come from the table.
        struct.pack_into('<iii', a, 160 + 16, 0, 0, 0)
        struct.pack_into('<iii', a, 192 + 16, -1, 1, 0)
        struct.pack_into('<iiiiii', a, 256, -2, 0, -2, 0, 2, 0)
        struct.pack_into('<iiiiii', a, 352, -2, 0, 1, 1, 1, 3)
        parsed = dict(names=['/Game/Other', 'Scene', 'Root'], exports=[
            dict(index=1, name='Root', outer=0), dict(index=2, name='Scene_2', outer=1)])
        return a, parsed

    def test_template_path_uses_import_outer_not_export_class_name(self):
        a, parsed = self.fixture()
        rows = module.references(a, parsed)['references']
        self.assertEqual(rows[rows[1]['template_index']]['path'], '/Game/Other.Scene')
        self.assertEqual(rows[2]['path'], '/Game/Lift.Root.Scene_2')
        self.assertEqual(rows[2]['template_index'], 1)
        self.assertEqual(len(bytes.fromhex(rows[-2]['table_bytes'])), 32)

    def test_missing_target_is_rejected_instead_of_joined_by_name(self):
        a, parsed = self.fixture()
        struct.pack_into('<i', a, 256 + 8, -3)
        with self.assertRaisesRegex(ValueError, 'outside package'):
            module.references(a, parsed)

    def test_cycle_and_invalid_name_rejected(self):
        for address, value in [(160 + 16, -2), (192 + 20, 900), (192 + 24, -1)]:
            a, parsed = self.fixture()
            struct.pack_into('<i', a, address, value)
            with self.assertRaises(ValueError):
                module.references(a, parsed)

    def test_table_boundary_and_export_layout_disagreement_rejected(self):
        a, parsed = self.fixture()
        with self.assertRaisesRegex(ValueError, 'outside package'):
            module.references(a[:447], parsed)
        a, parsed = self.fixture()
        parsed['exports'][0]['outer'] = 1
        with self.assertRaisesRegex(ValueError, 'layout differs'):
            module.references(a, parsed)


if __name__ == '__main__':
    unittest.main()
