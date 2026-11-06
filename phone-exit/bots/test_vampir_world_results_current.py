"""Select and Finish transfers require separate source proofs and strict cache identity."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load():
    path = HERE / 'resource-tools/vampir/verify-world-results-current.py'
    spec = importlib.util.spec_from_file_location('world_results_current_test', path)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


class WorldResultsCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load()
        cls.pointer = cls.tool.verify()
        cls.report = json.loads(Path(cls.pointer['report']).read_bytes())

    def test_select_clamp_changes_and_distinct_finish_baseline(self):
        self.assertEqual(self.report['packet_compatibility'], {'110': True, '206': True})
        select, finish = (self.report['roles'][name] for name in ('110', '206'))
        self.assertNotEqual(select['baseline_sha256'], finish['baseline_sha256'])
        self.assertEqual({row['field']: (row['before'], row['after']) for row in select['scalar_changes']},
            {'player+0x1d8 item+8': (91, 97), 'player+0x250 item+9': (7, 8)})
        self.assertEqual((select['roots'], finish['roots'], finish['math_ranges']), (56, 29, 9))
        self.assertFalse(self.report['runtime_admitted'])

    def test_cache_reuses_transfer_and_rejects_changed_boundary(self):
        with patch.object(self.tool, 'transfer', side_effect=AssertionError('world source transfer repeated')):
            warm = self.tool.verify()
        self.assertEqual(warm['sha256'], self.pointer['sha256'])
        self.assertTrue(warm['reused'])
        forged = copy.deepcopy(self.report)
        forged['packet_compatibility']['110'] = False
        with self.assertRaisesRegex(ValueError, 'cached report boundary differs'):
            self.tool.validate(forged, self.report['definition'])


if __name__ == '__main__':
    unittest.main()
