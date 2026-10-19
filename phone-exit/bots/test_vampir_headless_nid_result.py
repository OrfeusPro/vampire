"""Pinned public NID email result projection and policy gate evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).parent


class NidResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = HERE / 'resource-tools/vampir/inspect-nid-auth-result.py'
        spec = importlib.util.spec_from_file_location('nid_result_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.source.ROOT / 'code-clues/nid-auth-result-evidence.json').read_text('utf-8'))

    def test_reproducible_reviewed_helpers_bound_to_saved_script(self):
        self.assertEqual(self.tool.build(), self.report)
        folder = self.tool.source.ROOT / 'auth-web-snapshots' / self.tool.source.SNAPSHOT
        script = (folder / 'auth.js').read_bytes()
        self.assertEqual(hashlib.sha256(script).hexdigest(), self.report['script_sha256'])
        for row in self.report['functions'].values():
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(script[row['byte_offset']:row['byte_offset'] + len(data)], data)
            self.assertEqual(hashlib.sha256(data).hexdigest(), row['sha256'])
        self.assertFalse(self.report['account_authentication_attempted'])
        self.assertFalse(self.report['native_execution'])

    def test_email_result_is_access_token_and_refresh_choice_not_authorization_code(self):
        cases = self.report['replay']['outputs']
        self.assertEqual(len(cases), 4)
        for case in cases:
            self.assertEqual(case['events'][0], {'kind': 'reset'})
            event = case['events'][1]
            url = urlsplit(event['url'])
            self.assertEqual((url.scheme, url.netloc, url.path), ('nmthered', 'nmidprovider', '/result'))
            fields = parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
            self.assertEqual(fields, {k: [v] for k, v in dict(channelKey='mailUserKey', resultCode='0',
                accessToken='access-fixture +&', easyLoginToken='easy-fixture', issueType='fixture',
                netmarbleId='user-fixture', joinedCountryCode='UA',
                refreshToken='' if case['can_keep'] and not case['remember'] else 'refresh-fixture').items()})
            self.assertEqual(event['type'], 'result')
            self.assertEqual(len(case['events']), 2)

    def test_profile_gate_and_distinct_auth_modes(self):
        cases = self.report['replay']['dispatch']
        self.assertEqual(len(cases), 8)
        for case in cases:
            mode, allowed = case['auth_type'], case['profile_allowed']
            if mode == 'guestLinkIDP':
                expected = ['guest-link']
            elif mode == 'gameLauncherLinkIDP':
                expected = ['profile', 'launcher-link']
            elif mode == 'activate':
                expected = ['profile', 'activate-complete'] if allowed else ['profile']
            else:
                expected = ['profile', 'result', 'timer:500'] if allowed else ['profile']
            self.assertEqual(case['events'], expected)
        # Full profile processing is deliberately static, not replaced by a claimed successful login.
        profile = bytes.fromhex(self.report['functions']['profile_fetch']['bytes']).decode('utf-8')
        self.assertIn('j8.get("/user/info",{headers:{accessToken:e}})', profile)
        processing = bytes.fromhex(self.report['functions']['profile_processing']['bytes']).decode('utf-8')
        self.assertIn('await H(a)', processing)
        self.assertIn('USER_NOT_ALLOWED', processing)

    def test_native_result_route_and_fields_have_initializer_provenance(self):
        path = HERE / 'resource-tools/vampir/build-headless-nid-result.py'
        spec = importlib.util.spec_from_file_location('native_nid_result_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = json.loads((tool.config.native.ROOT / 'code-clues/headless-nid-result.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        bindings = {row['global_address']: row['source']['text'] for row in report['bindings']}
        self.assertEqual(bindings[0x14b564508], 'result')
        self.assertEqual(bindings[0x14b5644e8], 'signin')
        self.assertEqual(bindings[0x14b5645b8], 'accessToken')
        self.assertEqual(bindings[0x14b5645c8], 'refreshToken')
        self.assertEqual(bindings[0x14b5645d8], 'netmarbleId')
        self.assertEqual(bindings[0x14b5645e8], 'joinedCountryCode')
        self.assertEqual(bindings[0x14b5645a8], 'resultCode')
        rows = {row['address']: row for f in report['fragments'] for row in f['instructions']}
        self.assertEqual(rows[0x1450ed832]['rip_references'], [0x14b564508])
        self.assertEqual(rows[0x1450ed92b]['direct_target'], 0x1450ee6b0)
        self.assertEqual(rows[0x1450ed949]['direct_target'], 0x1450f08a0)
        self.assertTrue(any('::OnResult(' in row['text'] for row in report['diagnostics']))
        self.assertFalse(report['native_execution'])


if __name__ == '__main__':
    unittest.main()
