"""Offline native property-copy bounds for the installed release."""
import importlib.util
from pathlib import Path
import unittest


class PresetDefaultCopyTests(unittest.TestCase):
    def test_source_size_bounds(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-preset-default-copy.py'
        spec = importlib.util.spec_from_file_location('preset_default_copy_test', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        _, report = module.run()
        self.assertEqual(len(report['cases']), 36)
        parent_cases = [c for c in report['cases'] if c['source_size'] == 0x30]
        self.assertEqual(sum(c['copied'] for c in parent_cases), 2)
        self.assertTrue(all(not c['copied'] for c in parent_cases if c['offset'] >= 0x30))
        self.assertTrue(all(c['guards_unchanged'] for c in report['cases']))


if __name__ == '__main__':
    unittest.main()
