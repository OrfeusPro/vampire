"""Source CSV bytes through native tokenizer and zero service gate, offline."""
import importlib.util
from pathlib import Path
import unittest


class QuestCsvRowTests(unittest.TestCase):
    def test_original_quest_rows_and_lexical_boundaries(self):
        path = Path(__file__).parent/'resource-tools/vampir/replay-quest-csv-row-11316.py'
        spec = importlib.util.spec_from_file_location('quest_csv_row', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        target, result = module.run()
        self.assertTrue(target.is_file())
        self.assertFalse(result['network_used'])
        self.assertFalse(result['order_admitted'])
        self.assertTrue(result['native_execution'])
        self.assertEqual(len(result['cases']), 14)
        source = [c for c in result['cases'] if c['source']]
        self.assertEqual(len(source), 6)
        self.assertTrue(all(len(c['cells']) == 17 and c['cells'][-1] == '' and c['zero_gate'] for c in source))
        self.assertTrue(all(c['eof_cleared'] for c in result['cases']))
        self.assertEqual(result['fixtures']['atoi'], 6)
        self.assertEqual(result['fixtures']['clear'], 14)
        self.assertGreater(result['fixtures']['grow'], 0)
        self.assertEqual(result['fixtures']['copy'], 121)


if __name__ == '__main__':
    unittest.main()
