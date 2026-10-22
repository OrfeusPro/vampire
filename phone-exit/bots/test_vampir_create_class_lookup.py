import importlib.util
from pathlib import Path
import unittest


class CreateClassLookupTests(unittest.TestCase):
    def test_sparse_rows_distinguish_selected_type_from_result_id(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-create-class-lookup.py'
        spec = importlib.util.spec_from_file_location('creation_lookup_replay', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 45)
        self.assertTrue(any(row['slots'] == 35 and row['row_index'] == 32 for row in report['cases']))
        for row in report['cases']:
            if row['row_id'] is not None:
                self.assertNotEqual(row['selected_type'], row['row_id'])
            if row['selected_type'] in (0, 99, 100, 255):
                self.assertIsNone(row['row_id'])


if __name__ == '__main__': unittest.main()
