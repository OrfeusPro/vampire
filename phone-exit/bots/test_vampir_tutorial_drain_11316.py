"""Native ID9905 queue consumer order/readiness/cleanup with bounded fixtures."""
import importlib.util
from pathlib import Path
import unittest

class TutorialDrain11316Tests(unittest.TestCase):
    def test_current_consumer_retains_early_queue_and_drains_once_in_order(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-tutorial-drain-11316.py'
        spec=importlib.util.spec_from_file_location('tutorial_drain_native_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        _,report=module.run()
        self.assertEqual(report['source_sha256'],'d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960')
        self.assertTrue(report['native_execution']);self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']),160)
        self.assertEqual(sum(r['resumed'] for r in report['cases']),80)
        self.assertEqual({r['released'] for r in report['cases']},{0,1,2,3})

if __name__=='__main__':unittest.main()
