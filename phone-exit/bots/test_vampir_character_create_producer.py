"""Whole native producer control flow and wire, without dispatching a game packet."""
import importlib.util
from pathlib import Path
import unittest


class CharacterCreateProducerTests(unittest.TestCase):
    def test_producer_dispatch_and_wire(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-character-create-producer.py'
        spec = importlib.util.spec_from_file_location('create_producer_test', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        _, report = module.run()
        self.assertEqual(len(report['cases']), 37)
        self.assertEqual(sum(c['dispatched'] for c in report['cases']), 13)
        self.assertFalse(report['network_used'])
        for case in report['cases']:
            self.assertTrue(case['input_guards_unchanged'])
            self.assertEqual(case['dispatched'], case['raw_class'] != report['sentinel'] and case['player_state_present'])
            if case['dispatched']:
                self.assertEqual(case['raw_flags'], [0, 0])
                self.assertEqual(case['item_count'], 0)
                self.assertEqual(case['expected_result_id'], 104)
        candidate = next(c for c in report['cases'] if c['model_candidate'])
        self.assertEqual(candidate['raw_class'], 3)
        self.assertEqual(candidate['appearance'], [1, 8, 16, 9, 2, 2, 2, 9, 0, 0])
        self.assertTrue(report['model_candidate']['model_only'])
        self.assertFalse(report['model_candidate']['verified_loaded_asset'])
        self.assertTrue(any(c['dispatched'] and c['name'] == '' for c in report['cases']))


if __name__ == '__main__': unittest.main()
