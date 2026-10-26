"""Native record construction/copy inside actual map insertion and growth."""
import importlib.util
from pathlib import Path
import unittest


class QuestRecordChainTests(unittest.TestCase):
    def test_record_constructor_and_copy_survive_insert_growth_rehash(self):
        root = Path(__file__).parent/'resource-tools/vampir'
        spec = importlib.util.spec_from_file_location('quest_record_chain', root/'replay-quest-map-chain-11316.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        target, result = module.run(root/'knowledge/native-contexts/quest-record-chain-11316.json')
        self.assertTrue(target.is_file())
        self.assertTrue(result['native_record_constructor'])
        self.assertFalse(result['network_used'])
        self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['runs']), 6)
        primary = [r for r in result['runs'] if r['primary']]
        self.assertEqual(len(primary), 3)
        self.assertEqual(sum(r['callbacks']['native_record_checked'] for r in primary), 210)
        self.assertTrue(all(r['callbacks']['temporary_zero'] == 70 for r in primary))
        self.assertTrue(all(r['callbacks']['empty_wide'] == 70 for r in primary))
        self.assertTrue(all(r['callbacks']['empty_copy'] == 210 for r in primary))
        self.assertTrue(all('construct' not in r['callbacks'] for r in result['runs']))
        self.assertEqual(sum(r['existing_lookups'] for r in result['runs']), 840)


if __name__ == '__main__':
    unittest.main()
