import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('recognition',Path(__file__).parent/'vampir/recognition.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class Recognition(unittest.TestCase):
    def setUp(self):
        self.a=[{'prompt':'other','source_tutorial':{'tutorial_id':'b','step_id':'b1'}},{'prompt':'previous','source_tutorial':{'tutorial_id':'a','step_id':'a1'}},{'prompt':'next','source_tutorial':{'tutorial_id':'a','step_id':'a4'}}]
        self.config={'tutorial_actions':self.a,'_chain_catalog':{'steps':{'a2':{'type':'18','nextInTable':'a3'},'a3':{'type':'4','nextInTable':'a4'},'a4':{'type':'16'}}}}
    def test_next_source_step_first_and_all_other_actions_retained(self):
        q={'recognized_prompt':'previous','last_observed_tutorial':{'tutorial_id':'a','expected_next_observation':'a2'}}
        result=r.tutorial_candidates(self.config,q)
        self.assertEqual([a['prompt'] for a in result],['next','previous','other'])
        self.assertEqual(self.config['tutorial_actions'],self.a)
    def test_unknown_source_does_not_remove_candidates(self):
        self.assertEqual(len(r.tutorial_candidates(self.config,{'last_observed_tutorial':{'expected_next_observation':'missing'}})),3)
    def test_cycle_terminates(self):
        self.config['_chain_catalog']['steps']['a2']['nextInTable']='a2'
        self.assertEqual(len(r.tutorial_candidates(self.config,{'last_observed_tutorial':{'expected_next_observation':'a2'}})),3)
    def test_classification_is_based_on_matched_source_owner(self):
        self.assertEqual(r.screen_kind({'wbp':'WBP_ItemInfoPopup'}),'item_info_tutorial')
        self.assertEqual(r.screen_kind({'widget':'InventoryUI'}),'inventory_tutorial')

if __name__=='__main__':unittest.main()
