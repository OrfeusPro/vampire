"""Relocated call displacement must not hide the current continuation anchor."""
import unittest
from test_vampir_update_contracts import load
from pathlib import Path
class ContinuationCandidates11320Tests(unittest.TestCase):
 def test_relocated_anchor_resolves_without_semantic_admission(self):
  tool=load('align-login-continuation-11320');path,r=tool.run(Path('F:/PhoneExit Resources/Vampir'))
  self.assertEqual(tool.digest(path),path.parent.name)
  self.assertNotIn('state',r)
  self.assertEqual(r['context']['anchors'][-1]['address'],'0x14679e68e')
  self.assertEqual(r['context']['getter'],'0x1464b26a0')
  self.assertEqual(r['context']['singleton'],'0x14b6014a8')
  self.assertFalse(r['semantic_verification']);self.assertFalse(r['profile_activated']);self.assertFalse(r['network_used'])
if __name__=='__main__':unittest.main()
