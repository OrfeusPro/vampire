"""Registered result gate/model dispatch with explicit projection/lifecycle fixtures."""
import importlib.util
from pathlib import Path
import unittest

class QuestResultApplicationTests(unittest.TestCase):
    def test_registered_key_state_progress_and_gate_branch(self):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('quest_result_application',root/'replay-quest-result-application-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        target,r=module.run()
        self.assertTrue(target.is_file());self.assertFalse(r['network_used']);self.assertFalse(r['action_confirmation_admitted'])
        self.assertEqual(len(r['cases']),192)
        self.assertEqual(r['registration']['handler_slots'][-1],'0x1467b27a0')
        for c in r['cases']:
            admitted=c['result']==0 or c['result']==0x1197 and not c['special_gate']
            self.assertEqual(bool(c['applied']),admitted)
            if admitted:
                self.assertEqual(c['applied'],[dict(kind='existing' if c['existing'] else 'new',key=c['key'],state=c['state'],index=c['index'],flag=1)])
                self.assertEqual('new-record' in c['calls'],not c['existing'])
            if c['result']==10:self.assertFalse(c['applied'])
            self.assertEqual('error' in c['calls'],not c['special_gate'] and c['result']!=0)

if __name__=='__main__':unittest.main()
