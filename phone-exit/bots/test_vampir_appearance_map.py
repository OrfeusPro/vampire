import importlib.util
from pathlib import Path
import unittest


class AppearanceMapTests(unittest.TestCase):
    def test_native_insert_update_collision_and_sparse_reuse(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-appearance-map.py'
        spec = importlib.util.spec_from_file_location('appearance_map_check', path)
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 26)
        for collision in (False, True):
            rows = [row for row in report['cases'] if row['collision'] == collision]
            self.assertEqual([row['slots'] for row in rows[:10]], list(range(1, 8)) + [7, 7, 7])
            self.assertEqual([len(row['values']) for row in rows[10:]], [1, 2, 3])
            self.assertEqual([row['free_count'] for row in rows[10:]], [34, 33, 32])
            self.assertEqual(rows[-1]['occupied_slots'], [0, 1, 34])
            self.assertTrue(all(row['guards_unchanged'] for row in rows))
            self.assertEqual(rows[6]['values']['Head'], '00000080')  # Native store retains signed zero.
            if collision: self.assertGreater(rows[7]['comparisons'], 0)
        self.assertEqual(len(report['predicate_cases']), 64)
        for row in report['predicate_cases']:
            self.assertEqual(row['matches'], row['wanted'] == row['row_type'])


if __name__ == '__main__': unittest.main()
