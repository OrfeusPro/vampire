"""Current initial stats reuse the closed Select reader and exact native EStat IDs."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


class InitialStatsCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/verify-initial-stats-current.py'
        spec = importlib.util.spec_from_file_location('initial_stats_current_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.result = cls.tool.verify()
        cls.report = json.loads(Path(cls.result['report']).read_bytes())

    def test_current_fields_and_native_pair_provenance(self):
        self.assertEqual(self.report['vital_ids'], {'Level': 3, 'Hp': 4, 'MaxHp': 5, 'Mp': 9, 'MaxMp': 10})
        self.assertEqual(len(self.report['enums']['EStat']), 208)
        self.assertEqual(self.report['layout']['player_field'], '0x1c8')
        self.assertEqual(sum(row['records'] for row in self.report['inherited_pair_cases']), 13)
        self.assertFalse(self.report['runtime_admitted'])

    def test_cached_proof_skips_field_and_enum_analysis(self):
        with patch.object(self.tool, 'source_links', side_effect=AssertionError('Initial layout repeated')), \
                patch.object(self.tool, 'enums', side_effect=AssertionError('EStat scan repeated')):
            self.assertEqual(self.tool.verify(), dict(self.result, reused=True))

    def test_changed_vital_descriptor_cannot_pass_validation(self):
        forged = copy.deepcopy(self.report)
        next(row for row in forged['enums']['EStat'] if row['name'] == 'EStat::Hp')['value'] = 9
        with self.assertRaisesRegex(ValueError, 'EStat vital IDs differ'):
            self.tool.validate(forged, self.report['definition'])


if __name__ == '__main__':
    unittest.main()
