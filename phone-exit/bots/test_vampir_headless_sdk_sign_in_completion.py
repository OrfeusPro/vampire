"""Internal sign-in state and callback call site, no real game session claim."""
import importlib.util
import json
from pathlib import Path
import unittest


class SdkSignInCompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-sdk-sign-in-completion.py'
        spec=importlib.util.spec_from_file_location('sdk_completion_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/sdk-sign-in-completion-replay.json').read_text('utf-8'))

    def test_source_and_native_setsignin_body(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(len(self.report['cases']),16)
        rows={r['address']:r for f in self.report['extra_fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x14454c457]['operands'],'byte ptr [rcx + 0x400], bl')
        self.assertTrue(any('UNMServiceSettings::SetSignIn(bool)' in v['text'] for v in self.report['literals']))
        self.assertFalse(self.report['network_ready'])

    def test_idp_info_and_credential_code(self):
        cases={c['fixture']['name']:c for c in self.report['cases']}
        for credential in (None,33):
            case=cases['missing-None-credential-'+str(credential)]
            self.assertEqual(case['idp_info'],[{'channelCode':33}])
            self.assertEqual(case['channel_byte'],100 if credential is None else 33)
            self.assertEqual(case['sign_in_byte'],1)
            self.assertTrue(case['callback_seen'])
        self.assertEqual(cases['missing-idpInfo-credential-33']['idp_info'],['old-idp-fixture'])
        self.assertEqual(cases['missing-resultData-credential-33']['channel_byte'],1)
        self.assertEqual(cases['missing-accessToken-credential-33']['sdk_access_token'],'old-sdk-token-fixture')
        self.assertEqual(cases['missing-resultData-credential-33']['sign_in_byte'],1)

    def test_changed_player_and_early_error_boundaries(self):
        cases={c['fixture']['name']:c for c in self.report['cases']}
        same=cases['old-player-new-player-fixture']
        changed=cases['old-player-NEW-PLAYER-FIXTURE']
        self.assertFalse(any(e['action']=='changed_player_followup_capture' for e in same['events']))
        self.assertTrue(any(e['action']=='changed_player_followup_capture' for e in changed['events']))
        for name in ('reject-500-None','reject-200-1'):
            self.assertFalse(cases[name]['callback_seen'])
            self.assertEqual(cases[name]['sign_in_byte'],0)
        for case in self.report['cases']:
            if case['callback_seen']:
                self.assertEqual([e for e in case['events'] if e['action']=='result_dispatch_capture'],
                                 [dict(action='result_dispatch_capture',original_response_shared=True)])


if __name__=='__main__':
    unittest.main()
