"""Native field traversal evidence; no complete sign-in/session validation."""
import importlib.util
import json
from pathlib import Path
import unittest


class SdkSignInResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-sdk-sign-in-response-fields.py'
        spec = importlib.util.spec_from_file_location('sdk_signin_response_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/sdk-sign-in-response-fields-replay.json').read_text('utf-8'))

    def test_source_report_reproduces_and_ctor_keys_match(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual(len(self.report['cases']), 13)
        self.assertEqual(self.report['cases'][0]['constructor_keys'], {
            '0x20':'playerInfo', '0x28':'player', '0x30':'playerId', '0x38':'playerStatus',
            '0x40':'gameRegion', '0x48':'idpInfo', '0x50':'joinedCountryCode'})
        self.assertFalse(self.report['network_ready'])
        literals = {v['instruction']: v['text'] for v in self.report['literals']}
        self.assertEqual(literals[0x1411b00d4], 'accessToken')
        self.assertEqual(literals[0x1411b0314], 'errorCode')
        self.assertEqual(literals[0x1411b0584], 'resultData')

    def test_http_range_and_optional_field_preservation(self):
        cases = {c['fixture']['name']:c for c in self.report['cases']}
        for status in (199,207):
            self.assertEqual(cases['http-'+str(status)]['stage'], 'http_outside_200_206')
        for status in (200,201,206):
            c = cases['http-'+str(status)]
            self.assertEqual(c['stage'], 'player_fields_processed')
            self.assertEqual(c['sdk_access_token'], 'new-sdk-token-fixture')
            self.assertEqual(c['game_region'], 'region-fixture')
        for field in ('resultData','playerInfo','player'):
            self.assertEqual(cases['missing-'+field]['stage'], 'no_'+field)
        self.assertEqual(cases['missing-accessToken']['sdk_access_token'], 'old-sdk-token-fixture')
        self.assertEqual(cases['missing-gameRegion']['game_region'], 'old-region-fixture')
        self.assertEqual(cases['missing-playerId']['sdk_access_token'], 'new-sdk-token-fixture')

    def test_settings_arguments_and_save_failure_do_not_stop_slice(self):
        cases = {c['fixture']['name']:c for c in self.report['cases']}
        full = cases['http-200']
        setters = [e for e in full['events'] if e['action']=='settings_setter_capture']
        self.assertEqual(setters, [dict(action='settings_setter_capture',target=0x14454bc50,value='new-player-fixture',flag=False),
                                  dict(action='settings_setter_capture',target=0x14454b8c0,value='UA',flag=False)])
        self.assertEqual([e for e in full['events'] if e['action']=='Save_capture'],
                         [dict(action='Save_capture',returned=False)])
        status_events = [e for e in full['events'] if e['action']=='player_status_object_capture']
        self.assertEqual(len(status_events),2)
        self.assertTrue(all(e['value']=={'fixture':'player-status'} for e in status_events))
        self.assertFalse(any(e['action']=='player_status_object_capture' for e in cases['missing-playerStatus']['events']))
        self.assertFalse(any(e['action']=='Save_capture' for e in cases['missing-playerId']['events']))


if __name__ == '__main__':
    unittest.main()
