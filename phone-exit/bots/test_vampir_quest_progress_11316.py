"""Current whole native progress projection with explicit synthetic boundaries."""
import importlib.util
from pathlib import Path
import unittest


class QuestProgressTests(unittest.TestCase):
    def test_whole_projection_and_signed_index_boundaries(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-quest-progress-11316.py'
        spec=importlib.util.spec_from_file_location('quest_progress_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        saved,report=module.run()
        self.assertTrue(saved.is_file())
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']),324)
        self.assertTrue(any(c['index']==255 and c['found'] for c in report['cases']))
        self.assertTrue(any(c['index']==127 and not c['found'] for c in report['cases']))


if __name__=='__main__':unittest.main()
