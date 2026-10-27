"""Whole writer field order and failure propagation using existing current exports."""
import unittest
from test_vampir_update_contracts import load
class PacketContracts11320Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tool=load('verify-entry-contracts-11320');_,cls.result=cls.tool.run('writers')
 def test_every_field_failure_and_whole_writer_guards(self):
  for name,count in (('game-version',56),('game-login',104)):
   r=self.result['reports'][name];self.assertEqual(len(r['cases']),count)
   self.assertTrue(all(c['guards'] for c in r['cases']))
   self.assertTrue(any(c['fail_at'] is not None for c in r['cases']))
   self.assertFalse(r['network_used']);self.assertFalse(r['profile_activated'])
 def test_changed_fields_and_table_are_rejected(self):
  verify=load('verify-packet-writer-context').verify
  c=self.tool.context('game-version');fields=c['contract']['writer_check_by_source'][self.tool.SOURCE]['fields'];fields[0],fields[1]=fields[1],fields[0]
  with self.assertRaises(ValueError):verify(c,self.tool.ROOT)
  c=self.tool.context('game-version');c['contract']['data_dependencies'][self.tool.SOURCE]['packet-table']['address']='0x140000001'
  with self.assertRaises(ValueError):verify(c,self.tool.ROOT)
if __name__=='__main__':unittest.main()
