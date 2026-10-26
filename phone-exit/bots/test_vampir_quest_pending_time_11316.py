"""Actual native Time completion feeds native pending queue and deduplication."""
from collections import Counter
import importlib.util
from pathlib import Path
import unittest

class QuestPendingTimeTests(unittest.TestCase):
    def test_same_quest_dedup_index_type_key_guard_and_growth(self):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('quest_pending_time',root/'replay-quest-time-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        target,result=module.run(root/'knowledge/native-contexts/quest-pending-time-11316.json')
        self.assertTrue(target.is_file());self.assertTrue(result['native_pending'])
        self.assertFalse(result['network_used']);self.assertFalse(result['action_admitted'])
        self.assertEqual(len(result['cases']),34)
        self.assertEqual(set(Counter(c['mode'] for c in result['cases']).values()),{2})
        for c in result['cases']:
            mode=c['mode'];rows=c['pending_entries']
            if mode in ('open','record-advances'):
                self.assertEqual(c['pending_counts'],[0,0,1,1,1]);self.assertEqual(c['calls'].count('pending-grow'),1)
            if mode=='open':self.assertEqual(c['requests'],[0,0,1,1,2])
            if mode in ('pending-same','pending-other-index'):
                self.assertEqual(c['pending_counts'],[1]*5)
                self.assertNotIn('pending-guard',c['calls']);self.assertNotIn('pending-grow',c['calls'])
                if mode=='pending-other-index':self.assertEqual(rows[0]['properties']['QuestTaskIndex'],(c['index']+1)%6)
            if mode in ('pending-other-type','pending-other-key'):
                self.assertEqual(c['pending_counts'],[1,1,2,2,2]);self.assertEqual(c['calls'].count('pending-grow'),1)
                self.assertEqual(c['calls'].count('pending-guard'),1)
                self.assertEqual(rows[-1],{'kind':1,'properties':{'QuestInfoId':110120,'QuestTaskIndex':c['index']}})
            if mode=='pending-other-type':self.assertEqual([r['kind'] for r in rows],[2,1])
            if mode=='pending-other-key':self.assertEqual([r['properties']['QuestInfoId'] for r in rows],[110121,110120])
            if mode=='pending-guard':
                self.assertEqual(c['pending_counts'],[0]*5);self.assertEqual(c['calls'].count('pending-guard'),2)
                self.assertEqual(c['requests'],[0,0,1,1,2])

if __name__=='__main__':unittest.main()
