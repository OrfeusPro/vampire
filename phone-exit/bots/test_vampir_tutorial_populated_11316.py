"""Current tutorial existing-record application; all inputs synthetic."""
import importlib.util
from pathlib import Path
import unittest

class TutorialPopulated11316Tests(unittest.TestCase):
    def test_current_native_map_collision_and_record_updates(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-tutorial-populated-11316.py'
        spec=importlib.util.spec_from_file_location('tutorial_populated_native_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        _,report=module.run()
        self.assertEqual(report['source_sha256'],'d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960')
        self.assertTrue(report['native_execution']);self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']),384)
        self.assertEqual({r['selector'] for r in report['cases']},{0,2,0xffffffff})
        self.assertEqual({r['state'] for r in report['cases']},{0,1,2,3})
        self.assertEqual(sum(r['local_present'] for r in report['cases']),192)

if __name__=='__main__':unittest.main()
