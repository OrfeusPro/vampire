"""Whole native region lookup integrated with service setup; no real config writes."""
from collections import Counter
import importlib.util
from pathlib import Path
import unittest


class QuestServiceRegionTests(unittest.TestCase):
    def test_primary_legacy_and_missing_region_paths(self):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('quest_service_region',root/'replay-quest-service-setup-11316.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target,result=module.run(root/'knowledge/native-contexts/quest-service-region-11316.json')
        self.assertTrue(target.is_file()); self.assertTrue(result['native_lookup'])
        self.assertFalse(result['network_used']); self.assertFalse(result['active_region_verified']); self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['cases']),216)
        self.assertEqual(Counter(c['lookup_path'] for c in result['cases']),dict(primary=72,legacy=72,missing=72))
        self.assertTrue(all(c['calls'][-1]=='write:RegionSelect_PreLogin' for c in result['cases'] if c['lookup_path']=='legacy'))
        self.assertTrue(all(not any(v.startswith('write:') for v in c['calls']) for c in result['cases'] if c['lookup_path']!='legacy'))


if __name__=='__main__': unittest.main()
