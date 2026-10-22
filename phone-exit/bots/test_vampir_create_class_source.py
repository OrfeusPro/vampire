import importlib.util
from pathlib import Path
import unittest


class CreateClassSourceTests(unittest.TestCase):
    def test_native_creation_source_keeps_invalid_ui_distinct_from_class_zero(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-create-class-source.py'
        spec = importlib.util.spec_from_file_location('creation_class_replay', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 144)
        self.assertEqual(report['sentinel'], 0)
        valid_count = 0
        for row in report['cases']:
            valid = not row['disabled'] and row['present'] and row['type_case'] == 'match'
            valid_count += valid
            self.assertEqual(row['class_result'], row['raw_class'] if valid else 0)
            self.assertEqual(row['initial_appearance'], row['raw_appearance'] if valid else 0xa5)
            if row['disabled']: self.assertEqual(row['lookup_calls'], [])
        self.assertEqual(valid_count, 12)


if __name__ == '__main__': unittest.main()
