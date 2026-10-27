"""Actual readiness predicates integrated with native Time lifecycle."""
import importlib.util
from pathlib import Path
import unittest

class QuestTimeGatesTests(unittest.TestCase):
    def test_native_predicates_gate_actual_timer_and_completion(self):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('quest_time_gates',root/'replay-quest-time-11316.py')
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        target,r=m.run(root/'knowledge/native-contexts/quest-time-gates-11316.json')
        self.assertTrue(target.is_file());self.assertTrue(r['native_gates']);self.assertFalse(r['network_used']);self.assertFalse(r['action_admitted'])
        self.assertEqual(len(r['cases']),34)
        for c in r['cases']:
            if c['mode'] in ('open','gate-mode3-match','gate-flag-match'):
                self.assertEqual(c['requests'],[0,0,1,1,2]);self.assertEqual(c['states'],[1,0xffffffff,1,0xffffffff,1])
            elif c['mode']=='record-advances':self.assertEqual(c['requests'],[0,0,1,1,1])
            else:self.assertEqual(c['requests'],[0]*5)
            if c['mode'] in ('gate-one','gate-two','missing-model','gate-record-null','gate-data-null','gate-flag-mismatch'):
                self.assertEqual(c['elapsed'],[0.]*5);self.assertEqual(c['states'],[1]*5)
            self.assertEqual(c['calls'].count('blocked-instance'),5 if c['mode']=='gate-flag-mismatch' else 0)
            if c['mode']=='gate-mode3-match':self.assertNotIn('gate-data-flag',c['calls'])
            if c['mode']=='gate-one':self.assertNotIn('gate-data-flag',c['calls']);self.assertIn('gate-environment-kind',c['calls'])

if __name__=='__main__':unittest.main()
