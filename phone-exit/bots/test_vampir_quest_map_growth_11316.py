"""Native map metadata/order with explicit allocation/hash boundaries."""
import importlib.util
from pathlib import Path
import unittest


class QuestMapGrowthTests(unittest.TestCase):
    def test_rehash_preserves_slots_and_growth_preserves_metadata(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-quest-map-growth-11316.py'
        spec=importlib.util.spec_from_file_location('quest_map_growth',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        target,result=module.run()
        self.assertTrue(target.is_file());self.assertFalse(result['network_used']);self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['rehash_cases']),120);self.assertEqual(len(result['growth_cases']),16)
        self.assertTrue(any(c['count']==35 for c in result['rehash_cases']))


if __name__=='__main__':unittest.main()
