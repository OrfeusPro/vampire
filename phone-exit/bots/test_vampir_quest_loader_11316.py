"""Whole native loader control flow on original CSV rows, with declared fixtures."""
import importlib.util
from pathlib import Path
import unittest


class QuestLoaderTests(unittest.TestCase):
    def test_original_rows_fill_records_and_preserve_group_insertion_order(self):
        path = Path(__file__).parent/'resource-tools/vampir/replay-quest-loader-11316.py'
        spec = importlib.util.spec_from_file_location('quest_loader',path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        target,result = module.run()
        self.assertTrue(target.is_file())
        self.assertFalse(result['network_used'])
        self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['runs']),2)
        forward,reverse = result['runs']
        self.assertEqual(reverse['task_ids'],list(reversed(forward['task_ids'])))
        for run in result['runs']:
            self.assertEqual(run['records'],6)
            self.assertEqual(run['group_count'],1)
            self.assertEqual(run['bytes_read'],1220)
            self.assertTrue(run['group_order_matches_records'])
            self.assertEqual(run['callbacks']['column'],16)
            self.assertEqual(run['callbacks']['node_resize'],3)
            self.assertEqual(run['callbacks']['group_array_resize'],2)
            self.assertEqual(run['callbacks']['override_fixture'],1)


if __name__ == '__main__':
    unittest.main()
