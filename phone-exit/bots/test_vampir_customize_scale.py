import importlib.util
from pathlib import Path
import unittest


class CustomizeScaleTests(unittest.TestCase):
    def test_whole_constructor_initializes_scale_and_empty_owner(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-customize-scale.py'
        spec = importlib.util.spec_from_file_location('customize_scale_check', path)
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertEqual(report['class_name'], 'CharacterCustomizeUI')
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 6)
        for case in report['cases']:
            if case['object_present']:
                self.assertEqual(case['scale'], 1000)
                self.assertEqual(case['preset_ids'], [-1, -1])
                self.assertEqual(case['owner_pointer'], 0)
                self.assertTrue(case['guards_unchanged'])
            else: self.assertEqual(case['events'], [])


if __name__ == '__main__': unittest.main()
