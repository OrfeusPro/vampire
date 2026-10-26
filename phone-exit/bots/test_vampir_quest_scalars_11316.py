"""All current numeric cells through native wrappers and local Windows CRT."""
import importlib.util
from pathlib import Path
import unittest


class QuestScalarsTests(unittest.TestCase):
    def test_current_catalog_values_lexical_edges_and_column_bounds(self):
        path = Path(__file__).parent/'resource-tools/vampir/replay-quest-scalars-11316.py'
        spec = importlib.util.spec_from_file_location('quest_scalars',path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target,result = module.run()
        self.assertTrue(target.is_file())
        self.assertFalse(result['network_used']); self.assertFalse(result['order_admitted'])
        self.assertEqual(result['source_rows'],5944)
        self.assertEqual(result['source_values'],95104)
        self.assertEqual(len(result['source_cases']),26906)
        self.assertEqual(result['source_mismatches'],[])
        self.assertEqual(len(result['lexical_cases']),28)
        self.assertEqual(len(result['bounds']),15)
        self.assertEqual({c['kind'] for c in result['source_cases']},{'u64','i32','boolean','byte','f32'})
        self.assertEqual({c['name'] for c in result['imported']},{'atoi','_atoi64','strtoul','pow'})


if __name__ == '__main__':
    unittest.main()
