"""Current cold CDO bounded evidence and unchanged reuse."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


class CurrentViperColdCDOTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/verify-viper-cold-cdo-current.py'
        spec = importlib.util.spec_from_file_location('viper_cold_cdo_current', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.result = cls.tool.verify()

    def test_receipt_preserves_scope_without_replay(self):
        with patch.object(self.tool, 'execute', side_effect=AssertionError('Unexpected cold CDO replay')):
            self.assertEqual(self.tool.verify(), dict(self.result, reused=True))
        report = json.loads(Path(self.result['report']).read_bytes())
        self.assertFalse(report['loaded_preset_verified'])
        self.assertFalse(report['runtime_admitted'])
        self.assertEqual(len(report['native_cases']), 3)
        report['loaded_preset_verified'] = True
        with self.assertRaisesRegex(ValueError, 'boundary differs'):
            self.tool.validate(report, report['definition'])

    def test_changed_context_rejected_before_execution(self):
        with patch.object(self.tool, 'digest', return_value='0' * 64), patch.object(self.tool, 'execute') as run:
            with self.assertRaisesRegex(ValueError, 'input changed'):
                self.tool.verify()
            run.assert_not_called()
