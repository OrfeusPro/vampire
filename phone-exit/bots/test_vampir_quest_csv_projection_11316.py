"""Current CSV/native Type dataflow; explicitly not active quest admission."""
import importlib.util
import json
from pathlib import Path
import unittest


class QuestCsvProjectionTests(unittest.TestCase):
    def test_current_csv_types_use_actual_native_getter_with_unknown_live_order(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-quest-csv-projection-11316.py'
        spec=importlib.util.spec_from_file_location('quest_csv_projection',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run()
        self.assertTrue(artifact.is_file());self.assertFalse(result['network_used'])
        self.assertEqual(result['native_cases'],5944);self.assertEqual(result['quest_groups'],1353)
        self.assertFalse(result['active_step_admitted']);self.assertFalse(result['csv_order_admitted'])
        self.assertEqual(result['unprojected'],[])
        tasks=result['catalog']['110120']
        self.assertEqual([t['fields']['Id'] for t in tasks],['110120005','110120010','110120020','110120030','110120040','110120070'])
        self.assertEqual(json.loads(tasks[0]['fields']['Param']),{'type':'Time','seconds':0.1})
        self.assertEqual(json.loads(tasks[2]['fields']['Param'])['dialogGroupId'],11012002)


if __name__=='__main__':unittest.main()
