"""Current constructors and tag consumers, scoped source contract regressions."""
import copy,unittest
from types import SimpleNamespace
from unittest.mock import patch
from test_vampir_update_contracts import load
class TagContracts11320Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tool=load('verify-entry-contracts-11320');_,cls.result=cls.tool.run('tags')
 def test_current_tag_id_name_constructor_and_consumers(self):
  reports=self.result['reports']
  self.assertEqual(reports['game-version']['binding']['tag'],reports['game-login']['binding']['tag'])
  for name,r in reports.items():
   self.assertEqual(len(r['cases']),4);self.assertTrue(all(c['guards'] for c in r['cases']))
   self.assertEqual(r['source_sha256'],self.tool.SOURCE);self.assertFalse(r['network_used']);self.assertFalse(r['profile_activated'])
  self.assertEqual(reports['game-version']['binding']['packet_id'],1)
  self.assertEqual(reports['game-login']['binding']['packet_id'],3)
 def test_changed_reviewed_data_and_id_are_rejected(self):
  verify=load('verify-version-login-context').verify
  for change in ('data','id'):
   c=self.tool.context('game-version')
   if change=='data':c['contract']['data_dependencies'][self.tool.SOURCE]['tag-pointer']['address']='0x140000001'
   else:c['contract']['tag_check_by_source'][self.tool.SOURCE]['packet_id']=99
   with self.subTest(change=change),self.assertRaises(ValueError):verify(c,self.tool.ROOT)
 def test_preparation_proposals_require_exact_baseline_and_reject_conflict(self):
  tool=load('verify-entry-contracts-11320');model=load('update-contracts').load(load('knowledge-index').api(),load('knowledge-index').KNOWLEDGE)
  contract=next(c for c in model['contracts'] if c['id']=='game-version');contract['bindings'][tool.SOURCE].pop('wrapper-constructor')
  original=tool.load
  with patch.object(tool,'load',side_effect=lambda name:SimpleNamespace(load=lambda *args:model) if name=='update-contracts' else original(name)):
   proposal=tool.binding_proposals();self.assertEqual(proposal['bindings'],{'wrapper-constructor':'0x1467cf830'})
   self.assertFalse(proposal['runtime_activated'])
   contract['bindings'][tool.SOURCE]['wrapper-constructor']='0x140000001'
   with self.assertRaisesRegex(ValueError,'binding conflict'):tool.binding_proposals()
if __name__=='__main__':unittest.main()
