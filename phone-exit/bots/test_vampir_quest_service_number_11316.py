"""Whole region lookup with native numeric reader and coexisting identity keys."""
from collections import Counter
import importlib.util
from pathlib import Path
import unittest

class QuestServiceNumberTests(unittest.TestCase):
    def test_identity_scoped_numeric_read_and_fallback(self):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('quest_service_number',root/'replay-quest-service-setup-11316.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target,result=module.run(root/'knowledge/native-contexts/quest-service-number-11316.json')
        self.assertTrue(target.is_file()); self.assertTrue(result['native_number'])
        self.assertFalse(result['network_used']); self.assertFalse(result['active_region_verified']); self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['cases']),1008)
        self.assertEqual(set(Counter(c['profile'] for c in result['cases']).values()),{168})
        for c in result['cases']:
            mode=c['number_scenario']
            reads=[v for v in c['calls'] if v.startswith('read:')]
            writes=[v for v in c['calls'] if v.startswith('write:')]
            self.assertEqual(reads[0],'read:'+c['primary_key'])
            self.assertEqual(len(reads),1 if mode.startswith('primary') else 2)
            self.assertEqual(len(writes),2 if mode.startswith('legacy') else 0)
            expected={'primary-empty':[''],'primary-junk':['JP'],'primary-comma':['1000'],'legacy-seven':['7'],'legacy-junk':['JP'],'missing':[]}.get(mode)
            if expected is not None:self.assertEqual(c['converted'],expected)
            if mode=='primary-profile':
                value={'absent':1,'empty':1,'account-a':4,'account-b':7,'failed-subsystem':0,'new-subsystem':1000}[c['profile']]
                self.assertEqual(c['region'],value); self.assertEqual(c['converted'],[str(value)])
            if mode in ('primary-empty','primary-junk','legacy-junk'):self.assertEqual(c['region'],0)
            if mode=='missing':self.assertEqual(c['region'],55)

if __name__=='__main__':unittest.main()
