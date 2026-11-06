"""Offline composition of current game evidence and source configuration."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'
SPEC = importlib.util.spec_from_file_location('game_candidate_current_test', HERE / 'build-game-candidate-current.py')
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class GameCandidateCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path, cls.sha, cls.value = TOOL.publish()

    def test_assembly_retains_current_source_tag_and_separate_entry_proofs(self):
        self.assertEqual(self.value['game_profile']['compiled_tag'], self.value['compiled_tag_binding']['tag'])
        self.assertEqual(self.value['game_profile']['app_version'], '1.13.22')
        self.assertEqual(self.value['game_profile']['compiled_tag'], '4138E0A8C7421BE4F7F7078FF635DAD5')
        self.assertEqual(set(self.value['entry_proofs']), set(TOOL.ENTRY_CHECKS))
        for pointer in self.value['entry_proofs'].values():
            self.assertEqual(self.value['inputs'][str(Path(pointer['path']).resolve())], pointer['sha256'])
        self.assertFalse(self.value['runtime_admitted'])
        self.assertIn('current-viper-creation-admission', self.value['blockers'])

    def test_unchanged_candidate_verification_needs_no_analysis(self):
        original = TOOL.load

        def load(path):
            if path.name != 'knowledge-index.py':
                raise AssertionError('Checking a frozen candidate must not load replay tools')
            return original(path)

        with patch.object(TOOL, 'load', side_effect=load):
            self.assertEqual(TOOL.verify_report(self.path, self.sha), self.value)

    def test_stale_installed_source_rejected_before_proof_reads(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'ProjectRED-Win64-Shipping.exe'
            path.write_bytes(b'next patch')
            with self.assertRaisesRegex(ValueError, 'input SHA differs'):
                TOOL.build(installed=path)

    def test_mutated_retained_input_rejects_cached_candidate(self):
        original = TOOL.digest
        damaged = Path(self.value['entry_proofs']['character-list-current']['path']).resolve()
        with patch.object(TOOL, 'digest', side_effect=lambda p:
                '0' * 64 if Path(p).resolve() == damaged else original(p)):
            with self.assertRaisesRegex(ValueError, 'input SHA differs'):
                TOOL.verify_report(self.path, self.sha)

    def test_candidate_cannot_grant_network_admission(self):
        changed = dict(self.value, network_ready=True)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            path = TOOL.load(HERE / 'audit-client-release.py').save_snapshot(root / 'game-source-candidates-current', changed)
            with self.assertRaisesRegex(ValueError, 'boundary differs'):
                TOOL.verify_report(path, TOOL.digest(path), root=root)


if __name__ == '__main__':
    unittest.main()
