"""Source-bound VersionResult handler and all explicit switch indices."""
import copy,json,unittest
from pathlib import Path
from test_vampir_update_contracts import HERE,load
class VersionHandler11320Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.context=json.loads((HERE/'knowledge/native-contexts/version-result-handler-11320.json').read_bytes())
  cls.tool=load('verify-version-result-handler-context');cls.root=Path('F:/PhoneExit Resources/Vampir')
 def test_current_whole_handler_reader_and_switch(self):
  r=self.tool.verify(self.context,self.root)
  self.assertEqual((len(r['cases']),len(r['input_cases']),len(r['input_construction_cases']),len(r['switch_cases'])),(16,16,72,227))
  self.assertFalse(r['network_used']);self.assertFalse(r['profile_activated'])
 def test_older_gate_name_and_wrong_registration_are_rejected(self):
  c=copy.deepcopy(self.context);c['switch_gate']='version-gate-11318'
  with self.assertRaisesRegex(ValueError,'Unreviewed gate'):self.tool.verify(c,self.root)
  c=copy.deepcopy(self.context);c['registration_window']['sha256']='0'*64
  with self.assertRaisesRegex(ValueError,'registration window'):self.tool.verify(c,self.root)
if __name__=='__main__':unittest.main()
