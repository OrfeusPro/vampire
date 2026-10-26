"""Native Time callback/start/tick/timer/completion with source CSV durations."""
from collections import Counter
import importlib.util
from pathlib import Path
import unittest

class QuestTimeTests(unittest.TestCase):
    def test_two_phase_timer_gates_named_request_and_no_state_advance(self):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('quest_time',root/'replay-quest-time-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        target,result=module.run()
        self.assertTrue(target.is_file());self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_used']);self.assertFalse(result['action_admitted'])
        self.assertEqual(len(result['cases']),24)
        self.assertEqual(Counter(c['task_id'] for c in result['cases']),{'110120005':12,'110120070':12})
        for c in result['cases']:
            self.assertEqual(c['calls'][:2],['type','seconds'])
            self.assertEqual(c['seconds'],0.1 if c['task_id']=='110120005' else 1)
            if c['mode']=='open':
                self.assertEqual(c['states'],[1,0xffffffff,1,0xffffffff,1])
                self.assertEqual(c['requests'],[0,0,1,1,2])
            elif c['mode']=='record-advances':
                self.assertEqual(c['requests'],[0,0,1,1,1])
            else:self.assertEqual(c['requests'],[0]*5)
            if c['mode']=='missing-model':self.assertEqual(c['calls'].count('lookup'),2)
            if c['mode'].startswith('start-'):self.assertNotIn('broadcast',c['calls'])

if __name__=='__main__':unittest.main()
