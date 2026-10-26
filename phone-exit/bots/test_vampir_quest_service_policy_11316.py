"""Nonzero group gate/native policy, bounded explicit manager state."""
import importlib.util
from pathlib import Path
import unittest


class QuestServicePolicyTests(unittest.TestCase):
    def test_nonzero_group_lists_and_inclusive_version_bounds(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-quest-service-policy-11316.py'
        spec=importlib.util.spec_from_file_location('quest_service_policy',path)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target,result=module.run()
        self.assertTrue(target.is_file()); self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_used']); self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['cases']),30)
        for external in (False,True):
            cases={c['name']:c for c in result['cases'] if c['external_buckets']==external}
            self.assertEqual(len(cases),15)
            for name in ('at-min','middle','at-max','allow','zero-server','nonmatching-lists'):
                self.assertEqual(cases[name]['skip'],0)
            for name in ('empty','missing','empty-array','type-mismatch','deny','deny-before-allow','version-missing','below-min','above-max'):
                self.assertEqual(cases[name]['skip'],1)
            self.assertNotIn('version_lookup',cases['allow']['callbacks'])
            self.assertNotIn('allow_split',cases['deny-before-allow']['callbacks'])


if __name__=='__main__': unittest.main()
