import importlib.util
from pathlib import Path
import unittest


class GenderPathTests(unittest.TestCase):
    def test_native_source_enum_selects_male_m_and_female_f(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-gender-paths.py'
        spec = importlib.util.spec_from_file_location('gender_path_check', path)
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 1024)
        self.assertEqual(report['enum_rows'], [dict(name='EGenderType::' + name, value=value)
            for name, value in [('Male', 0), ('Female', 1), ('Max', 2)]])
        for row in report['cases']:
            expected = ('M', 'F', 'M')[row['value']] if row['enum_present'] and row['value'] < 3 else ''
            self.assertEqual(row['suffix'], expected)
            self.assertTrue(row['guards_unchanged'])
            self.assertTrue(row['path'].endswith(expected))
        self.assertEqual(sum(row['value'] == 1 and row['suffix'] == 'F' for row in report['cases']), 2)


if __name__ == '__main__': unittest.main()
