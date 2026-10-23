"""Source-bound native preset construction; no game or authorization."""
import importlib.util
from pathlib import Path
import unittest


class PresetInitializerTests(unittest.TestCase):
    def test_initializer_and_base_constructors(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-preset-initializer.py'
        spec = importlib.util.spec_from_file_location('preset_initializer_test', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        _, report = module.run()
        self.assertEqual(len(report['cases']), 24)
        self.assertEqual({c['flags'] for c in report['cases']}, {0, 1, 2, 3})
        self.assertEqual({c['callback_enabled'] for c in report['cases']}, {False, True})
        self.assertEqual(len(report['postconstruct_cases']), 6)
        for case in report['postconstruct_cases']:
            self.assertEqual(case['flags_before'], 0x231)
            self.assertEqual(case['flags_after'], 0x31)
            self.assertTrue(case['all_other_object_bytes_unchanged'])
            self.assertTrue(case['initializer_object_cleared'])
        for case in report['cases']:
            self.assertTrue(case['integer_fields_unchanged'])
            self.assertTrue(case['initializer_base_complete'])
            self.assertTrue(case['guards_unchanged'])
            self.assertEqual(case['floats'], [0.5] * 7)
            self.assertEqual(case['voice'], 0)


if __name__ == '__main__': unittest.main()
