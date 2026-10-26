"""Whole loader uses the proven native scalar paths rather than Python getters."""
import importlib.util
from pathlib import Path
import unittest


class QuestLoaderScalarsTests(unittest.TestCase):
    def test_original_rows_flow_through_native_scalars_into_records_and_groups(self):
        root = Path(__file__).parent/'resource-tools/vampir'
        spec = importlib.util.spec_from_file_location('quest_loader_scalars',root/'replay-quest-loader-11316.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target,result = module.run(root/'knowledge/native-contexts/quest-loader-scalars-11316.json')
        self.assertTrue(target.is_file()); self.assertTrue(result['native_scalars'])
        self.assertFalse(result['network_used']); self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['runs']),2)
        forward,reverse = result['runs']
        self.assertEqual(reverse['task_ids'],list(reversed(forward['task_ids'])))
        for run in result['runs']:
            self.assertEqual(run['records'],6); self.assertEqual(run['bytes_read'],1220)
            self.assertTrue(run['group_order_matches_records'])
            self.assertEqual(run['scalar_import_calls'],dict(atoi=48,_atoi64=18,strtoul=12,pow=24))
            self.assertEqual(run['callbacks']['override_fixture'],1)


if __name__ == '__main__':
    unittest.main()
