"""Real local CRT conversion through exact client leaves, no game actions."""
import importlib.util
from pathlib import Path
import unittest


class QuestEmptyGroupTests(unittest.TestCase):
    def test_blank_zero_numeric_sso_and_zero_filter(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-quest-empty-group-11316.py'
        spec=importlib.util.spec_from_file_location('quest_empty_group',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        target,result=module.run()
        self.assertTrue(target.is_file());self.assertFalse(result['network_used'])
        self.assertEqual(len(result['cases']),14);self.assertEqual(len(result['column_bounds']),3)
        self.assertEqual(sum(c['zero_gate_integrated'] for c in result['cases']),8)
        self.assertFalse(result['order_admitted'])


if __name__=='__main__':unittest.main()
