"""Existing matching task native replay, explicit lifecycle fixtures, no network."""
import importlib.util
from pathlib import Path
import unittest


class QuestStateApplicationTests(unittest.TestCase):
    def test_native_progress_copy_state_order_and_sender_index(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-quest-state-application-11316.py'
        spec=importlib.util.spec_from_file_location('quest_state_application',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run()
        self.assertFalse(result['network_used']);self.assertTrue(artifact.is_file())
        self.assertEqual(result['case_count'],324);self.assertEqual(len(result['task_tables']),23)
        self.assertEqual({r['callback'] for r in result['cases']},{'start','update'})


if __name__=='__main__':unittest.main()
