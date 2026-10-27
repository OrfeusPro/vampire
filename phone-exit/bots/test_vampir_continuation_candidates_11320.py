"""Current static automation must preserve its specific unresolved anchor."""
import unittest
from test_vampir_update_contracts import load
from pathlib import Path
class ContinuationCandidates11320Tests(unittest.TestCase):
 def test_actual_ambiguous_anchor_does_not_become_admission(self):
  tool=load('align-login-continuation-11320');path,r=tool.run(Path('F:/PhoneExit Resources/Vampir'))
  self.assertEqual(tool.digest(path),path.parent.name)
  self.assertEqual(r['state'],'requires_review');self.assertEqual(r['anchor'],'0x14679b6ff')
  self.assertNotIn('context',r);self.assertFalse(r['semantic_verification']);self.assertFalse(r['profile_activated']);self.assertFalse(r['network_used'])
if __name__=='__main__':unittest.main()
