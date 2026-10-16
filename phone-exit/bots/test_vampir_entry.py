import importlib.util
import unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('entry',Path(__file__).parent/'vampir/entry.py')
entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)

class Entry(unittest.TestCase):
    def setUp(self):
        self.state={};self.taps=[];self.visible={'prompt','logo','server'}
        self.config={'entry_title':{'prompt':'prompt','anchors':['logo'],'timeout_sec':20}}
        self.settings={}
    def call(self,command,**args):self.taps.append((command,args))
    def match(self,name):return {'found':name in self.visible,'point':[640,473]}
    def tick(self,now=1000):return entry.tick(self,self.settings,self.state,{'width':1280,'height':720},self.config,self.match,now)
    def test_only_one_attempt_with_20_second_wait(self):
        self.assertEqual(self.tick()['step'],'title_wait_transition')
        self.assertEqual(self.tick(1019)['step'],'title_wait_transition')
        self.assertEqual(self.tick(1020)['error'],'title_not_advanced')
        self.assertEqual(len(self.taps),1)
    def test_missing_title_anchor_never_taps(self):
        self.visible.remove('logo');self.assertTrue(self.tick()['pause']);self.assertFalse(self.taps)
    def test_no_profile_never_taps(self):
        self.config={};self.assertIsNone(self.tick());self.assertFalse(self.taps)
    def test_transition_allows_next_screen_but_never_repeated_title(self):
        self.tick();self.visible=set();self.assertIsNone(self.tick(1003))
        self.visible={'prompt','logo','server'};self.assertEqual(self.tick(1004)['step'],'title_reappeared');self.assertEqual(len(self.taps),1)
    def test_different_server_does_not_block_start(self):
        self.visible.discard('server');self.tick();self.assertEqual(len(self.taps),1)
    def test_title_to_selected_character_to_world(self):
        self.config['entry_character']={'prompt':'start','anchors':['character_header','last_login'],'timeout_sec':20,'control':'WBP_CharacterSelectUI/ButtonStart'}
        self.tick();self.visible={'start','character_header','last_login'}
        result=self.tick(1003);self.assertEqual(result['step'],'character_wait_transition')
        self.assertEqual(len(self.taps),2)
        self.visible=set();self.assertIsNone(self.tick(1006))
        self.assertEqual(len(self.taps),2)
    def test_character_selection_requires_anchors(self):
        self.config={'entry_character':{'prompt':'start','anchors':['character_header'],'timeout_sec':20}}
        self.visible={'start'};self.assertTrue(self.tick()['pause']);self.assertFalse(self.taps)
    def test_blinking_prompt_is_not_transition(self):
        self.tick();self.visible.remove('prompt')
        self.assertEqual(self.tick(1003)['step'],'title_wait_transition')
        self.assertNotIn('left_title',self.state['title_entry'])
        self.visible.add('prompt');self.assertEqual(self.tick(1020)['error'],'title_not_advanced')
        self.assertEqual(len(self.taps),1)
    def test_not_title_never_taps(self):
        self.visible={'server'};self.assertIsNone(self.tick());self.assertFalse(self.taps)

if __name__=='__main__':unittest.main()
