"""Preallocated native slot selection, not full CSV load/order admission."""
import importlib.util
from pathlib import Path
import unittest


class QuestSparseInsertTests(unittest.TestCase):
    def test_append_free_slot_and_zero_group_gate(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-quest-sparse-insert-11316.py'
        spec=importlib.util.spec_from_file_location('quest_sparse_insert',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run()
        self.assertTrue(artifact.is_file());self.assertFalse(result['network_used']);self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['insertion_cases']),96);self.assertEqual(len(result['filter_cases']),4)
        for case in result['insertion_cases']:
            self.assertEqual(case['slot'],case['count']-1 if case['reused_free_slot'] else case['count'])


if __name__=='__main__':unittest.main()
