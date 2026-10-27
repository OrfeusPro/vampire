"""Current-source admission through one cached entry package; no network."""
import unittest
from test_vampir_update_contracts import load
class CurrentEntry11320Tests(unittest.TestCase):
 def test_current_component_uses_source_bound_cached_package(self):
  runner=load('run-entry-batch-11320');_,batch,_=runner.run()
  for name in ['version-combiner', 'version-prepare-combiner']:
   report=batch['reports'][name]
   self.assertEqual(report['source_sha256'],runner.SHA)
   self.assertEqual(len(report['cases']),runner.COMPONENTS[name][1])
   self.assertFalse(report['network_used']);self.assertFalse(report['profile_activated'])
  self.assertFalse(batch['runtime_activated'])
if __name__=='__main__':unittest.main()
