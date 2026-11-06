"""Retain current LobbyLogin preparation evidence across repeated updates."""
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import unittest
from unittest.mock import patch


class CurrentLobbyLoginPrepareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/verify-lobby-login-prepare-current.py'
        spec = spec_from_file_location('lobby_login_prepare_current', path)
        cls.tool = module_from_spec(spec)
        spec.loader.exec_module(cls.tool)

    def test_frozen_package_reuses_preparation(self):
        first = self.tool.verify()
        with patch.object(self.tool, 'execute', side_effect=AssertionError('Unchanged preparation repeated')):
            self.assertEqual(self.tool.verify(), dict(first, reused=True))
        report = json.loads(Path(first['report']).read_bytes())
        windows = report['cases']['windows']
        self.assertEqual(windows['integers'], [2, 2, 387, 0])
        self.assertEqual(windows['providers'], ['nm', 'player', 'token', 'sdk_text', 'nid_text', 'metadata'])
        self.assertEqual(windows['wire']['request_id'], 3)
        self.assertEqual(windows['wire']['sequence_after'], 1)
        self.assertEqual(report['cases']['sdk-disabled']['providers'], ['nm'])
        self.assertFalse(report['runtime_admitted'])
        self.assertFalse(report['network_used'])
        del report['cases']['manager-missing']
        with self.assertRaisesRegex(ValueError, 'boundary'):
            self.tool.validate(report, report['definition'])

    def test_corrupt_context_rejected_before_execution(self):
        with patch.object(self.tool, 'digest', return_value='0' * 64), patch.object(self.tool, 'execute') as run:
            with self.assertRaisesRegex(ValueError, 'input changed'):
                self.tool.verify()
            run.assert_not_called()

    def test_update_guard_retains_output_and_rejects_another_source(self):
        guard = self.tool.load('entry-package-check-guard')
        index = self.tool.load('knowledge-index')
        material, pointer = guard.material(index, self.tool.ROOT, self.tool.SOURCE,
                                          'lobby-login-prepare-current')
        self.assertEqual(material[pointer['path']], pointer['sha256'])
        self.assertGreater(len(material), 20)
        with self.assertRaisesRegex(ValueError, 'source differs'):
            guard.material(index, self.tool.ROOT, '0' * 64, 'lobby-login-prepare-current')
        with patch.object(index, 'digest', return_value='0' * 64):
            with self.assertRaisesRegex(ValueError, 'hash differs'):
                guard.material(index, self.tool.ROOT, self.tool.SOURCE, 'lobby-login-prepare-current')
