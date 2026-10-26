"""Integrated native map chain; explicit external fixtures and no live admission."""
import importlib.util
from pathlib import Path
import unittest


class QuestMapChainTests(unittest.TestCase):
    def test_fresh_insert_growth_rehash_and_duplicate_lookup_keep_slot_order(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-quest-map-chain-11316.py'
        spec=importlib.util.spec_from_file_location('quest_map_chain',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        target,result=module.run()
        self.assertTrue(target.is_file());self.assertFalse(result['network_used']);self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['runs']),6)
        self.assertEqual(sum(r['insertions'] for r in result['runs']),420)
        self.assertEqual(sum(r['existing_lookups'] for r in result['runs']),840)
        self.assertTrue(all(len(r['capacity_transitions'])>=3 and len(r['bucket_transitions'])>=3 for r in result['runs']))


if __name__=='__main__':unittest.main()
