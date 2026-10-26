"""Native identity-dependent region key generation integrated with lookup/setup."""
from collections import Counter
import importlib.util
from pathlib import Path
import unittest


class QuestServiceKeyTests(unittest.TestCase):
    def test_two_identity_keys_and_prelogin_paths(self):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('quest_service_key',root/'replay-quest-service-setup-11316.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target,result=module.run(root/'knowledge/native-contexts/quest-service-key-11316.json')
        self.assertTrue(target.is_file()); self.assertTrue(result['native_key'])
        self.assertFalse(result['network_used']); self.assertFalse(result['active_region_verified']); self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['cases']),288)
        self.assertEqual(Counter(c['profile'] for c in result['cases']),{'absent':72,'empty':72,'account-a':72,'account-b':72})
        for case in result['cases']:
            expected='RegionSelect_'+case['profile'] if case['profile'].startswith('account-') else 'RegionSelect_PreLogin'
            self.assertEqual(case['primary_key'],expected)
            self.assertEqual(case['calls'][0],'read:'+expected)
            if case['lookup_path']=='legacy': self.assertEqual(case['calls'][-2:],['write:'+expected,'write:RegionSelect_PreLogin'])


if __name__=='__main__': unittest.main()
