"""Current fresh tutorial model path; no account or game network access."""
import importlib.util
from pathlib import Path
import unittest

class TutorialStartup11316Tests(unittest.TestCase):
    def test_current_whole_application_bootstrap_and_early_advance(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-tutorial-startup-11316.py'
        spec=importlib.util.spec_from_file_location('tutorial_startup_native_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        _,report=module.run()
        self.assertEqual(report['source_sha256'],'d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960')
        self.assertTrue(report['native_execution']);self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']),192)
        self.assertEqual({r['count'] for r in report['cases']},{0,1,16})
        self.assertEqual({r['state'] for r in report['cases']},{0,1,2,3})
        self.assertEqual(sum(bool(r['launched']) for r in report['cases']),16)

if __name__=='__main__':unittest.main()
