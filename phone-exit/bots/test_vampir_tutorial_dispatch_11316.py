"""Current native tutorial gate and queued deep-copy proof; no game traffic."""
import importlib.util
from pathlib import Path
import unittest

class TutorialDispatch11316Tests(unittest.TestCase):
    def test_whole_handler_gate_and_independent_queued_copy(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-tutorial-dispatch-11316.py'
        spec=importlib.util.spec_from_file_location('tutorial_dispatch_native_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        _,report=module.run()
        self.assertEqual(report['source_sha256'],'d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960')
        self.assertTrue(report['native_execution']);self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']),192)
        self.assertEqual(sum(r['deferred'] for r in report['cases']),64)
        self.assertEqual({r['count'] for r in report['cases']},{0,1,8,64})
        self.assertEqual({r['native_state'] for r in report['cases']},{0,5,6,7})
        self.assertEqual(sum(r['via_handler'] for r in report['cases']),64)

if __name__=='__main__':unittest.main()
