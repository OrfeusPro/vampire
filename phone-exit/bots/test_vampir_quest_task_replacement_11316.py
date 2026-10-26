"""Whole kind-6 factory/replacement with explicitly bounded external fixtures."""
import importlib.util
from pathlib import Path
import unittest


class QuestTaskReplacementTests(unittest.TestCase):
    def test_native_creation_replacement_fallback_and_reference_counts(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-quest-task-replacement-11316.py'
        spec=importlib.util.spec_from_file_location('quest_task_replacement',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run()
        self.assertTrue(artifact.is_file());self.assertFalse(result['network_used'])
        self.assertEqual(result['case_count'],378)
        self.assertEqual({c['mode'] for c in result['cases']},{'empty','previous','next'})
        self.assertEqual(sum(c['primary_allocation_failed'] for c in result['cases']),189)
        self.assertTrue(all(c['final_control_strong']==c['final_control_weak']==1 for c in result['cases']))


if __name__=='__main__':unittest.main()
