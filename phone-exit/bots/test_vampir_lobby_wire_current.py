"""Current native provider composition and immutable no-replay reuse."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent / 'resource-tools/vampir'


class CurrentLobbyWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('lobby_wire_current', HERE / 'verify-lobby-wire-current.py')
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)

    def test_current_frozen_wire_report_reused_without_native_execution(self):
        with patch.object(self.tool, 'execute', side_effect=AssertionError('unchanged native replay forbidden')):
            result = self.tool.verify()
        self.assertTrue(result['reused'])
        report = json.loads(Path(result['report']).read_bytes())
        self.assertEqual((len(report['cases']), len(report['prefixes']), len(report['failures'])), (8, 45, 8))
        self.assertFalse(report['runtime_admitted'])
        self.assertFalse(report['network_used'])
        self.assertTrue(report['extra']['accepted'])
        self.assertEqual(report['extra']['consumed'], 45)
        self.assertIn('lobby_current.py', '\n'.join(report['definition']['inputs']))

    def test_failed_or_missing_provider_result_cannot_be_cached_success(self):
        report = dict(source_sha256=self.tool.SOURCE, native_execution=True, network_used=False,
            runtime_admitted=False, limits=['fixture'], cases=[{'accepted': True}] * 8,
            prefixes=[{'accepted': False}] * 45, failures=[{'accepted': False}] * 8,
            extra={'accepted': True, 'consumed': 45})
        self.tool.validate(report)
        report['cases'][-1] = {'accepted': False}
        with self.assertRaisesRegex(ValueError, 'composition/boundary'):
            self.tool.validate(report)
        report['cases'][-1] = {'accepted': True}
        report['failures'][-1] = {'accepted': True}
        with self.assertRaisesRegex(ValueError, 'composition/boundary'):
            self.tool.validate(report)

    def test_changed_retained_input_fails_before_replay(self):
        with patch.object(self.tool, 'digest', return_value='0' * 64), patch.object(self.tool, 'execute') as execute:
            with self.assertRaisesRegex(ValueError, 'CharacterList pointer changed'):
                self.tool.verify()
            execute.assert_not_called()


if __name__ == '__main__': unittest.main()
