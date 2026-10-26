"""Native identity cache update integrated into region key/lookup/service setter."""
from collections import Counter
import importlib.util
from pathlib import Path
import unittest


class QuestServiceIdentityTests(unittest.TestCase):
    def test_identity_refresh_empty_and_failed_subsystem_cache_paths(self):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('quest_service_identity',root/'replay-quest-service-setup-11316.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target,result=module.run(root/'knowledge/native-contexts/quest-service-identity-11316.json')
        self.assertTrue(target.is_file()); self.assertTrue(result['native_identity'])
        self.assertFalse(result['network_used']); self.assertFalse(result['active_region_verified']); self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['cases']),432)
        self.assertEqual(Counter(c['profile'] for c in result['cases']),{p:72 for p in ('absent','empty','account-a','account-b','failed-subsystem','new-subsystem')})
        for c in result['cases']:
            if c['profile']=='failed-subsystem':
                self.assertIn('identity-init',c['calls']); self.assertNotIn('identity-fetch',c['calls'])
                self.assertEqual(c['primary_key'],'RegionSelect_cached-c')
            elif c['profile']=='new-subsystem':
                self.assertEqual(c['calls'].count('identity-init'),1); self.assertIn('identity-fetch',c['calls'])
                self.assertEqual(c['primary_key'],'RegionSelect_account-d')
            elif c['profile']=='absent': self.assertFalse(any(v.startswith('identity-') for v in c['calls']))


if __name__=='__main__': unittest.main()
