import io
import json
from pathlib import Path
import sys
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.nid_sdk_credential import NidSdkCredential
from vampir_core.sdk_fetch import plan_nid_sdk_fetch, parse_sdk_fetch_response, SdkFetchSummary
from vampir_core.sdk_sign_in_http import execute_sdk_fetch, SdkSignInHttpError
from test_vampir_sdk_sign_in_http import Response
import test_vampir_nid_sdk_runner as runner_fixtures


class SdkFetchTests(unittest.TestCase):
    def plan(self):
        return plan_nid_sdk_fetch(constants={'authUrl': 'https://sdk.example.invalid'},
            credential=NidSdkCredential('provider-fixture'), game_code='thered', build_code=0,
            nm_device_key='nm-fixture', device_key='device-fixture', country_code='UA', os_type='PC')

    def test_request_is_separate_from_sign_in_and_contains_no_device_payload(self):
        plan = self.plan()
        self.assertEqual(plan.url, 'https://sdk.example.invalid/v1/fetch-player')
        self.assertEqual(json.loads(plan.body), {'credential': {'channelCode': 33, 'channelAccessToken': 'provider-fixture'}, 'scope': 'channel'})
        self.assertEqual(dict(plan.headers), {'Content-Type': 'application/json', 'Accept': 'application/json', 'gameCode': 'thered', 'buildCode': 'A'})
        self.assertNotIn('provider-fixture', repr(plan))

    def test_summary_discards_identity_and_rejects_ambiguous_response(self):
        result = parse_sdk_fetch_response(status=200, body=b'{"errorCode":0,"resultData":{"playerInfo":{"private":"identity-fixture"}}}')
        self.assertEqual(result, SdkFetchSummary(True))
        self.assertNotIn('identity-fixture', repr(result))
        for body in (b'{"errorCode":0,"errorCode":0,"resultData":{}}',
                     b'{"errorCode":true,"resultData":{}}', b'{"errorCode":1203}',
                     b'{"errorCode":0,"resultData":[]}', b'{"errorCode":0,"resultData":{"x":NaN}}'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                parse_sdk_fetch_response(status=200, body=body)

    def test_one_http_request_and_no_continuation_on_1203(self):
        plan, calls = self.plan(), []
        def rejected(request, timeout):
            calls.append(request.full_url)
            raise urllib.error.HTTPError(plan.url, 400, 'private-server-text', {}, io.BytesIO(b'{"errorCode":1203,"message":"private-server-text"}'))
        with self.assertRaises(SdkSignInHttpError) as error:
            execute_sdk_fetch(plan, expected_url=plan.url, _open=rejected)
        self.assertEqual((error.exception.status, error.exception.sdk_code), (400, 1203))
        self.assertNotIn('private-server-text', str(error.exception))
        self.assertEqual(calls, [plan.url])
        accepted = execute_sdk_fetch(plan, expected_url=plan.url,
            _open=lambda *a, **k: Response(b'{"errorCode":0,"resultData":{}}'))
        self.assertEqual(accepted, SdkFetchSummary(True))
        with self.assertRaises(ValueError):
            execute_sdk_fetch(plan, expected_url='https://sdk.example.invalid/v1/sign-up', _open=lambda *a, **k: self.fail('Must not open'))

    def test_explicit_runner_fetch_stops_before_sign_in_or_creation(self):
        f = runner_fixtures.NidSdkRunnerTests
        f.setUpClass()
        calls = []
        def execute(plan, **kwargs):
            calls.append(plan.url)
            return SdkFetchSummary(True)
        with patch.object(f.runner, 'load_inputs', return_value=(f.binding, f.profile, f.constants)), \
             patch.object(f.runner, 'execute_sdk_sign_in', side_effect=AssertionError('No SignIn')), \
             patch.object(f.runner, 'execute_sdk_sign_up', side_effect=AssertionError('No SignUp')):
            result = f.runner.run('fixture@example.invalid', fetch_player=True,
                _capture=lambda *a, **k: f.provider, _execute=execute)
        self.assertEqual(result, SdkFetchSummary(True))
        self.assertEqual(calls, ['https://sdk.example.invalid/v1/fetch-player'])
        for kwargs in (dict(create_sdk_player=True), dict(auth_flow='launcher')):
            with patch.object(f.runner, 'load_inputs', side_effect=AssertionError('Must reject before auth')):
                with self.assertRaises(ValueError):
                    f.runner.run('fixture@example.invalid', fetch_player=True, **kwargs)


if __name__ == '__main__': unittest.main()
