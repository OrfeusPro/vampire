"""Explicit candidate boundary: real source evidence, no authentication in tests."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import Mock

HERE = Path(__file__).parent / 'vampir-headless'
spec = importlib.util.spec_from_file_location('candidate_profile_test', HERE / 'game-source-profile.py')
profile = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = profile
spec.loader.exec_module(profile)


class CandidateProfileTests(unittest.TestCase):
    def test_real_frozen_evidence_and_tag(self):
        value = profile.load_profile(selected_profile=profile.CANDIDATE)
        self.assertEqual(value.source_exe_sha256, profile.CURRENT_SHA)
        self.assertEqual(value.app_version, '1.13.16')
        self.assertEqual(value.compiled_tag, '32283C4C6485307BCF524765A84409C3')
        self.assertTrue(value.live_probe_only)
        self.assertFalse(value.active_game_cache_verified)
        self.assertEqual(profile.PROFILES['recovered-release'][1],
            '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e')

    def test_corrupt_report_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            import json
            evidence = json.loads((HERE / 'game-candidate-11316.json').read_text('utf-8'))
            first = Path(root) / evidence['reports'][0]['path']
            first.parent.mkdir(parents=True)
            first.write_bytes(b'corrupt')
            with patch.object(profile.json, 'loads', return_value=evidence):
                with self.assertRaisesRegex(ValueError, 'source changed'):
                    profile.verify_candidate_evidence(root=root)

    def test_missing_required_report_rejected(self):
        with patch.object(profile.json, 'loads', return_value={
                'source_sha256': profile.CURRENT_SHA, 'capabilities': ['version', 'login', 'character-list', 'initial-ping'],
                'live_verified': False, 'reports': []}):
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                profile.verify_candidate_evidence()

    def test_scope_cannot_promote_creation(self):
        with patch.object(profile.json, 'loads', return_value={
                'source_sha256': profile.CURRENT_SHA, 'capabilities': ['create'], 'live_verified': False}):
            with self.assertRaisesRegex(ValueError, 'scope changed'):
                profile.verify_candidate_evidence()

    def test_candidate_cdn_keeps_explicit_route(self):
        from test_vampir_headless_public_cdn import module as cdn, Response
        value = cdn.profile(profile.CANDIDATE)
        self.assertEqual(value['url'], cdn.CANDIDATE_URL)
        opener = Mock()
        opener.open.return_value = Response(url=cdn.CANDIDATE_URL)
        with patch.object(cdn.SocksRoute, 'opener', return_value=opener), \
                patch.object(cdn.urllib.request, 'build_opener', side_effect=AssertionError('Direct fallback')):
            body, metadata = cdn.fetch(value['url'], route=cdn.SocksRoute(1087))
        self.assertEqual(body, b'abc')
        self.assertEqual(metadata['socks5_loopback_port'], 1087)
