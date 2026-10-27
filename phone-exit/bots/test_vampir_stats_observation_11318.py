"""One observational boundary suite; current owner and game sockets are untouched."""
import importlib.util
from pathlib import Path
import unittest
from test_vampir_live_stats_observer_11318 import LiveStatsObserver11318Tests,batch
from test_vampir_observed_vitals_ui_11318 import ObservedVitalsUi11318Tests

HERE=Path(__file__).parent
class ObserverWorkerBoundary11318Tests(unittest.TestCase):
 def test_disposable_worker_checks_real_proofs_and_returns_scoped_observation(self):
  path=HERE/'vampir-headless/watch-live-session.py'
  spec=importlib.util.spec_from_file_location('stats_watch_boundary',path)
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  handler=HERE/'vampir-headless/observe-stats-11318.py'
  result=module.evaluate(handler,batch([(4,0,700),(5,0,1000)]))
  self.assertIsNone(result['error'])
  observed=result['values']['readonly_stats']
  self.assertEqual(observed['status'],'observed_partial')
  self.assertEqual(observed['vitals']['hp'],700)
  self.assertEqual(observed['character_key'],'42')
  self.assertFalse(observed['owner_character_modified'])
  waiting=batch();waiting['samples']['samples']=[];waiting['samples']['cursor']=0
  result=module.evaluate(handler,waiting)
  self.assertIsNone(result['error'])
  self.assertEqual(result['values']['readonly_stats']['status'],'waiting_for_notification')
  self.assertIsNone(result['values']['readonly_stats']['vitals']['hp'])

def load_tests(loader,tests,pattern):
 return unittest.TestSuite(loader.loadTestsFromTestCase(case) for case in (LiveStatsObserver11318Tests,ObservedVitalsUi11318Tests,ObserverWorkerBoundary11318Tests))
if __name__=='__main__':unittest.main()
