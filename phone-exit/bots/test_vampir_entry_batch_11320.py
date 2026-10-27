"""Current source preparation/result package; no login or network actions."""
import copy,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from test_vampir_update_contracts import load,HERE
ROOT=Path('F:/PhoneExit Resources/Vampir')
class EntryBatch11320Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.runner=load('run-entry-batch-11320');cls.path,cls.report,_=cls.runner.run()
 def context(self,name):return json.loads((HERE/'knowledge/native-contexts'/(name+'-11320.json')).read_bytes())
 def test_whole_source_bound_package(self):
  self.assertEqual(self.report['native_case_executions'],4622)
  self.assertEqual(set(self.report['reports']),set(self.runner.COMPONENTS))
  for name,r in self.report['reports'].items():
   self.assertEqual(r['source_sha256'],self.runner.SHA);self.assertEqual(len(r['cases']),self.runner.COMPONENTS[name][1])
   self.assertFalse(r['network_used']);self.assertFalse(r['profile_activated'])
  self.assertFalse(self.report['runtime_activated']);self.assertFalse(self.report['live_verified'])
 def test_cached_package_and_artifact_integrity(self):
  path,r,reused=self.runner.run();self.assertTrue(reused);self.assertEqual(path,self.path)
  for report in r['reports'].values():
   for item in report['evidence']:self.assertEqual(self.runner.digest(item['path']),item['sha256'])
 def test_current_login_tag_is_explicit_and_cannot_fall_back_to_old_value(self):
  tool=load('verify-login-prepare-context');c=self.context('login-prepare')
  self.assertNotEqual(c['compiled_tag_source']['value'],'32283C4C6485307BCF524765A84409C3')
  del c['compiled_tag_source']
  with self.assertRaisesRegex(ValueError,'explicit compiled tag'):tool.verify(c,ROOT)
  c=self.context('login-prepare');c['compiled_tag_source']['value']='0'*32
  with self.assertRaisesRegex(ValueError,'compiled tag differs'):tool.verify(c,ROOT)
 def test_wrong_source_export_and_calls_are_rejected(self):
  c=self.context('login-prepare');c['source_sha256']='0'*64
  with self.assertRaisesRegex(ValueError,'source path'):load('verify-login-prepare-context').verify(c,ROOT)
  c=self.context('version-prepare');c['exports'][next(iter(c['exports']))]='0'*64
  with self.assertRaisesRegex(ValueError,'export SHA'):load('verify-version-prepare-context').verify(c,ROOT)
  c=self.context('login-prepare');c['call_sites'].pop(next(iter(c['call_sites'])))
  with self.assertRaisesRegex(ValueError,'call sites'):load('verify-login-prepare-context').verify(c,ROOT)
 def test_version_result_projection_and_all_short_inputs(self):
  r=self.report['reports']['version-result']
  self.assertEqual((len(r['cases']),len(r['truncated']),len(r['failures']),len(r['construction_cases'])),(32,17,5,72))
 def test_isolated_cache_rejects_tamper_and_pointer_escape(self):
  # Bookkeeping fixture only; native evidence above is never modified.
  runner=load('run-entry-batch-11320');reports=copy.deepcopy(self.report['reports'])
  definition=copy.deepcopy(self.report['definition']);contexts={n:self.context(n) for n in runner.COMPONENTS}
  original=runner.load;tools={t:n for n,(t,_) in runner.COMPONENTS.items()}
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve()
   with patch.object(runner,'inputs',return_value=(contexts,definition)),patch.object(runner,'load',side_effect=lambda name:SimpleNamespace(verify=lambda c,r:reports[next(n for n,v in contexts.items() if v is c)]) if name in tools else original(name)):
    path,_,reused=runner.run(root);self.assertFalse(reused)
    self.assertTrue(runner.run(root)[2]);raw=path.read_bytes();path.write_bytes(raw+b' ')
    with self.assertRaisesRegex(ValueError,'cached report changed'):runner.run(root)
    path.write_bytes(raw);pointer=next((root/'knowledge/entry-batch-cache-11320').glob('*.json'))
    outside=root/'outside'/path.parent.name/'manifest.json';outside.parent.mkdir(parents=True);outside.write_bytes(raw)
    pointer.write_text(json.dumps(dict(report=str(outside),sha256=path.parent.name)),encoding='utf-8')
    with self.assertRaisesRegex(ValueError,'cached report changed'):runner.run(root)
if __name__=='__main__':unittest.main()
