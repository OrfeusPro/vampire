import importlib.util
from pathlib import Path
import unittest


class AppearanceResetTests(unittest.TestCase):
    def test_native_reset_clears_parameters_preserving_gender_and_guards(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-appearance-reset.py'
        spec = importlib.util.spec_from_file_location('appearance_reset_check', path)
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 24)
        for case in report['cases']:
            self.assertEqual(case['appearance'], [0] * 10)
            self.assertEqual(case['voice'], 0)
            self.assertEqual(case['map_slots_after'], 0)
            self.assertEqual(case['frees'], 1 + 2 * len(case['occupied']))
            self.assertTrue(case['gender_preserved'])
            self.assertTrue(case['guards_unchanged'])


if __name__ == '__main__': unittest.main()
