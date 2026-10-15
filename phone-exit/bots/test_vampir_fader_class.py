import importlib.util
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('fader_class',
    Path(__file__).parent / 'resource-tools/vampir/build-fader-class-link.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CookedSuperclass(unittest.TestCase):
    def fixture(self):
        data = bytearray(400)
        struct.pack_into('<i', data, 32, 4)
        struct.pack_into('<iiii', data, 40 + 28, 1, 100, 2, 200)
        struct.pack_into('<i', data, 104, -1)
        struct.pack_into('<iii', data, 216, -2, 0, 0)
        struct.pack_into('<iii', data, 248, 0, 1, 0)
        return data, dict(names=['NkFaderUI', '/Script/NkUMG'])

    def test_superclass_import_path_and_offsets(self):
        result = module.superclass(*self.fixture(), 1)
        self.assertEqual(result['path'], '/Script/NkUMG.NkFaderUI')
        self.assertEqual(result['superclass_field_offset'], 104)
        self.assertEqual([r['offset'] for r in result['import_chain']], [200, 232])

    def test_cycle_or_export_super_reference_rejected(self):
        for reference in [-1, 1, -3]:
            data, report = self.fixture()
            struct.pack_into('<i', data, 216, reference)
            with self.assertRaises(ValueError):
                module.superclass(data, report, 1)

    def test_outside_bounds_and_bad_name_rejected(self):
        for location, value in [(100 + 4, -3), (220, 100), (224, 1)]:
            data, report = self.fixture()
            struct.pack_into('<i', data, location, value)
            with self.assertRaises(ValueError):
                module.superclass(data, report, 1)
        with self.assertRaises(ValueError):
            module.superclass(*self.fixture(), 2)

    def test_non_script_package_rejected(self):
        data, report = self.fixture()
        report['names'][1] = '/Game/RED/UI/Other'
        with self.assertRaises(ValueError):
            module.superclass(data, report, 1)


if __name__ == '__main__':
    unittest.main()
