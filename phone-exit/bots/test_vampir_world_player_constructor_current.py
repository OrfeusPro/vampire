"""Changed current Select110 constructor proof and unchanged cache reuse."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


class CurrentWorldPlayerConstructorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/verify-world-player-constructor-current.py'
        spec = importlib.util.spec_from_file_location('world_player_constructor_current', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.result = cls.tool.verify()

    def test_retained_proof_is_reused_without_native_execution(self):
        with patch.object(self.tool, 'execute', side_effect=AssertionError('Unexpected constructor replay')):
            self.assertEqual(self.tool.verify(), dict(self.result, reused=True))
        report = json.loads(Path(self.result['report']).read_bytes())
        self.assertTrue(report['constructor_equivalent'])
        self.assertEqual(len(report['cases']), 8)
        self.assertEqual({row['seed'] for row in report['cases']}, {0, 1, 2, 3})
        self.assertEqual({row['object_alignment_offset'] for row in report['cases']}, {0, 8})
        self.assertEqual(set(report['pointer_relocations']), {'0x0', '0x28', '0x48'})
        self.assertFalse(report['runtime_admitted'])
        self.assertFalse(report['network_used'])
        inputs = report['definition']['inputs']
        for path in self.tool.load('native-publication-v2').runtime_files():
            self.assertEqual(inputs[str(path)], self.tool.digest(path))

    def test_failed_canary_cannot_be_accepted_as_cached_success(self):
        report = json.loads(Path(self.result['report']).read_bytes())
        report['cases'][0]['guards_preserved'] = False
        with self.assertRaisesRegex(ValueError, 'receipt scope differs'):
            self.tool.validate(report, report['definition'])

    def test_changed_baseline_proof_rejected_before_execution(self):
        with patch.object(self.tool, 'digest', return_value='0' * 64), patch.object(self.tool, 'execute') as execute:
            with self.assertRaisesRegex(ValueError, 'baseline semantic proof changed'):
                self.tool.verify()
            execute.assert_not_called()
