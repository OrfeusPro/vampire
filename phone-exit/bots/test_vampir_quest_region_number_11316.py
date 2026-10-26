"""Numeric region config: missing key differs from found nonnumeric text."""
import importlib.util
from pathlib import Path
import unittest

class QuestRegionNumberTests(unittest.TestCase):
    def test_found_flag_comma_removal_and_numeric_conversion(self):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('quest_region_number',root/'replay-quest-region-number-11316.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target,result=module.run()
        self.assertTrue(target.is_file())
        self.assertEqual(len(result['cases']),56)
        self.assertFalse(result['network_used'])
        self.assertFalse(result['active_region_verified'])
        self.assertFalse(result['order_admitted'])
        for c in result['cases']:
            self.assertEqual(c['found'],bool(c['result']))
            if c['found']:
                self.assertEqual([s[5:] for s in c['calls'] if s.startswith('wtoi:')],[c['text'].replace(',','')])
            else:
                self.assertIsNone(c['number'])
                self.assertFalse(any(s.startswith('wtoi:') for s in c['calls']))

if __name__=='__main__': unittest.main()
