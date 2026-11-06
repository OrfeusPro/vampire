"""Current lobby result source transfer, preserved projections and cache."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


class CurrentLobbyResultsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/verify-lobby-results-current.py'
        spec = importlib.util.spec_from_file_location('lobby_results_current', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.result = cls.tool.verify()

    def test_unchanged_transfer_reuses_all_materials(self):
        with patch.object(self.tool, 'transfer', side_effect=AssertionError('Unexpected source transfer')):
            self.assertEqual(self.tool.verify(), dict(self.result, reused=True))
        report = json.loads(Path(self.result['report']).read_bytes())
        self.assertEqual(len(report['pairs']), 14)
        self.assertEqual(report['tables'], 10)
        self.assertFalse(report['native_execution'])
        self.assertTrue(report['native_proofs_reused'])
        report['relocations'] -= 1
        with self.assertRaisesRegex(ValueError, 'boundary'):
            self.tool.validate(report, report['definition'])

    def test_changed_mapping_is_rejected(self):
        context, _, wire = self.tool.definition(self.tool.CONTEXT, self.tool.ROOT.resolve())
        context['mapping']['0x14574aa80'] = '0x14574eee1'
        with self.assertRaisesRegex(ValueError, 'closure differs'):
            self.tool.transfer(context, self.tool.ROOT.resolve(), wire)
