"""Static native field binding and current named ServerServiceGroup source data."""
import importlib.util
from pathlib import Path
import unittest


class QuestServiceDataTests(unittest.TestCase):
    def test_current_phase_and_region_candidates_remain_unadmitted(self):
        path=Path(__file__).parent/'resource-tools/vampir/inspect-quest-service-data-11316.py'
        spec=importlib.util.spec_from_file_location('quest_service_data',path)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target,result=module.run()
        self.assertTrue(target.is_file()); self.assertFalse(result['native_execution'])
        self.assertFalse(result['network_used']); self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['tables']['CSV/ServerServiceGroup.csv']['rows']),104)
        self.assertEqual(len(result['tables']['CSV/ServerGroup.csv']['rows']),417)
        self.assertEqual(result['server_256']['ServicePhase'],'10000')
        decisions={r['region_type']:r for r in result['candidate_decisions']}
        self.assertEqual(set(decisions),set(range(8)))
        self.assertTrue(all(not r['active_region_verified'] for r in decisions.values()))
        self.assertEqual({k for k,v in decisions.items() if not v['candidate_skip']},{0,1,2,3,4})
        self.assertEqual({k for k,v in decisions.items() if v['candidate_skip']},{5,6,7})


if __name__=='__main__': unittest.main()
