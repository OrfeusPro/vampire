"""Offline candidate scope, provenance and stale-proof guards; no authorization."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import load


class GameCandidate11318Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.builder=load('build-game-candidate-11318')

    def test_complete_real_candidate_is_repeatable_and_disabled(self):
        proofs=json.loads((Path(__file__).parent/'resource-tools/vampir/knowledge/native-contexts/game-candidate-proofs-11318.json').read_bytes())
        candidate=self.builder.build(proofs)
        self.assertEqual(len(candidate['reports']),16)
        self.assertEqual(candidate,self.builder.build(proofs))
        self.assertEqual(candidate['source_sha256'],self.builder.SHA)
        self.assertFalse(candidate['runtime_enabled'] or candidate['network_ready'] or candidate['live_verified'])

    def test_missing_proofs_reject_before_resource_reads(self):
        with patch.object(self.builder,'resource_profile',side_effect=AssertionError('Source read')):
            for proofs in ({}, {'unreviewed':{}}):
                with self.assertRaisesRegex(ValueError,'complete explicit current check set'):
                    self.builder.build(proofs)

    def test_corrupt_content_addressed_report_rejects(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'knowledge/check-results'/('0'*64)/'manifest.json'
            path.parent.mkdir(parents=True);path.write_text('{}')
            with patch.object(self.builder,'REQUIRED',frozenset(('native-waiting-end-context',))):
                with self.assertRaisesRegex(ValueError,'hash changed'):
                    self.builder.verify_checks({'native-waiting-end-context':dict(path=str(path),sha256='0'*64)},root)

    def test_historical_report_cannot_be_relabelled_current(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            payload=json.dumps(dict(state='passed',definition=dict(source_sha256='0'*64,check={}))).encode()
            sha=hashlib.sha256(payload).hexdigest();path=root/'knowledge/check-results'/sha/'manifest.json'
            path.parent.mkdir(parents=True);path.write_bytes(payload)
            with patch.object(self.builder,'REQUIRED',frozenset(('native-waiting-end-context',))):
                with self.assertRaisesRegex(ValueError,'source/state/definition differs'):
                    self.builder.verify_checks({'native-waiting-end-context':dict(path=str(path),sha256=sha)},root)

    def test_report_path_must_be_inside_public_proof_library(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with patch.object(self.builder,'REQUIRED',frozenset(('native-waiting-end-context',))):
                with self.assertRaisesRegex(ValueError,'outside current proof library'):
                    self.builder.verify_checks({'native-waiting-end-context':dict(path=str(root/'manifest.json'),sha256='0'*64)},root)

    def test_current_ini_and_tag_source_provenance(self):
        resource=self.builder.resource_profile(self.builder.ROOT)
        self.assertEqual(resource['source_sha256'],self.builder.SHA)
        self.assertEqual(resource['app_version'],'1.13.18')
        self.assertEqual(resource['compiled_tag'],self.builder.TAG)
        self.assertTrue(resource['cdn_url'].endswith('/1_13_18/config.json'))
        self.assertFalse(resource['config_precedence_verified'] or resource['active_game_cache_verified'])

    def test_candidate_flags_do_not_activate_runtime(self):
        # Scope assembly only: no claim that the substituted proof checker ran
        # native scenarios. The complete real check set is required by build().
        proofs={name:dict(path='fixture',sha256='0'*64) for name in self.builder.REQUIRED}
        with patch.object(self.builder,'verify_checks',return_value=proofs), \
                patch.object(self.builder,'resource_profile',return_value={'source_sha256':self.builder.SHA}):
            candidate=self.builder.build(proofs)
        self.assertEqual(candidate['capabilities'],list(self.builder.CAPABILITIES))
        self.assertNotIn('create',candidate['capabilities'])
        self.assertNotIn('quests',candidate['capabilities'])
        for key in ('runtime_enabled','live_verified','network_ready','profile_activated','baseline_promoted'):
            self.assertIs(candidate[key],False)


if __name__=='__main__':unittest.main()
