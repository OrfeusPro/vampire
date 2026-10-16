import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('recognition',Path(__file__).parent/'vampir/recognition.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Overlay(unittest.TestCase):
 def setUp(self):
  self.config={'fast_overlays':[{'id':'test','anchors':['a','b','c'],'blocked_by':['tutorial'],'close':'exit','wait_sec':2,'timeout_sec':10}]};self.state={};self.visible={'a','b','c','exit'}
 def match(self,name):return {'found':name in self.visible,'point':[10,10]}
 def tick(self,now):return r.overlay_route(self.config,self.state,self.match,now)
 def test_settle_once_then_unknown_result_pauses(self):
  self.assertEqual(self.tick(0)['step'],'screen_settle_test')
  self.assertIn('button',self.tick(2));self.assertNotIn('button',self.tick(3))
  self.assertTrue(self.tick(12)['pause']);self.assertNotIn('button',self.tick(13))
 def test_tutorial_blocks_exit(self):
  self.visible.add('tutorial');self.assertIsNone(self.tick(100));self.assertFalse(self.state)
 def test_partial_identity_does_not_route(self):
  self.visible.remove('c');self.assertIsNone(self.tick(100))
 def test_missing_target_pauses(self):
  self.visible.remove('exit');self.assertEqual(self.tick(100)['error'],'screen_exit_target_missing')
 def test_disappearance_clears_pending(self):
  self.tick(0);self.tick(2);self.visible=set();self.assertIsNone(self.tick(3));self.assertFalse(self.state)
if __name__=='__main__':unittest.main()
