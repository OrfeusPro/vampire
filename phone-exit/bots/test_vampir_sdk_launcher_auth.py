import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.nid_sdk_credential import NidSdkCredential
from vampir_core.sdk_launcher_auth import (LauncherToken, plan_nid_launcher_token,
    plan_launcher_sign_in, parse_launcher_token_response)
from vampir_core.sdk_sign_in_http import execute_launcher_token, execute_launcher_sign_in, SdkSignInHttpError
from test_vampir_sdk_sign_in_http import Response, BODY
import test_vampir_nid_sdk_runner as nid_fixtures


def context():
    return dict(constants={'authUrl': 'https://sdk.example.invalid/base'}, game_code='thered', build_code=0,
                nm_device_key='nm-fixture', device_key='device-fixture', country_code='JP', os_type='pc')


class SdkLauncherAuthTests(unittest.TestCase):
    def test_token_request_preserves_nid_credential_and_nests_game_build(self):
        source = Path('F:/PhoneExit Resources/Vampir/code-clues/sdk-sign-in-body-replay.json')
        native = json.loads(source.read_text('utf-8'))
        case = next(c for c in native['cases'] if c['fixture']['credential'] and not c['fixture']['playerId'])
        f = case['fixture']
        inputs = dict(context(), nm_device_key=f['nmDeviceKey'], device_key=f['deviceKey'], country_code=f['countryCode'], os_type=f['os'])
        plan = plan_nid_launcher_token(credential=NidSdkCredential(f['credential']['channelAccessToken']), **inputs)
        expected = json.loads(json.dumps(case['body']))
        expected['credential'].update(gameCode='thered', buildCode='A')
        self.assertEqual(json.loads(plan.body), expected)
        self.assertEqual(plan.url, 'https://sdk.example.invalid/base/launcher/token')
        self.assertNotIn('launcherToken', dict(plan.headers))
        self.assertNotIn('provider-token', repr(plan))

    def test_sign_in_custom_header_matches_native_capture_without_credential_body(self):
        native = json.loads(Path('F:/PhoneExit Resources/Vampir/code-clues/launcher-token-context-replay.json').read_text('utf-8'))
        for row in native['headers']:
            if not row['token_fixture']:
                with self.assertRaises(ValueError):
                    plan_launcher_sign_in(launcher_token=LauncherToken(''), **context())
                continue
            plan = plan_launcher_sign_in(launcher_token=LauncherToken(row['token_fixture']), **context())
            self.assertEqual([list(pair) for pair in plan.headers if pair[0] == 'launcherToken'], [row['header']])
            self.assertEqual(set(json.loads(plan.body)), {'nmDeviceKey', 'deviceKey', 'countryCode', 'os'})
            self.assertNotIn('channelCode', plan.body.decode())
            self.assertNotIn(row['token_fixture'], repr(plan))
        plan = plan_launcher_sign_in(launcher_token=LauncherToken('launcher-secret'), existing_sdk_token='old-sdk-secret', **context())
        headers = dict(plan.headers)
        self.assertEqual((headers['launcherToken'], headers['accessToken'], headers['authToken']),
                         ('launcher-secret', 'old-sdk-secret', 'old-sdk-secret'))
        for build, expected in ((1, 'B'), (2, 'C'), (255, 'A')):
            plan = plan_launcher_sign_in(launcher_token=LauncherToken('x'), **dict(context(), build_code=build))
            self.assertEqual(dict(plan.headers)['buildCode'], expected)

    def test_parser_requires_a_fresh_string_and_explicit_success(self):
        for code in (0, '0'):
            value = parse_launcher_token_response(status=200, body=json.dumps(dict(errorCode=code, resultData='opaque-token')).encode())
            self.assertEqual(value.value, 'opaque-token')
            self.assertNotIn('opaque-token', repr(value))
        invalid = [b'{}', b'{"resultData":"x"}', b'{"errorCode":false,"resultData":"x"}',
                   b'{"errorCode":0.0,"resultData":"x"}', b'{"errorCode":"00","resultData":"x"}',
                   b'{"errorCode":42,"resultData":"x"}', b'{"errorCode":0,"resultData":{"accessToken":"x"}}',
                   b'{"errorCode":0,"resultData":""}', b'{"errorCode":0,"resultData":"x\\nprivate"}',
                   b'{"errorCode":0,"resultData":"x","resultData":"y"}',
                   b'{"errorCode":0,"resultData":"x","extra":NaN}', b'x' * 65537,
                   json.dumps(dict(errorCode=0, resultData='x' * 8193)).encode()]
        for body in invalid:
            with self.subTest(size=len(body)), self.assertRaises(ValueError) as error:
                parse_launcher_token_response(status=200, body=body)
            self.assertNotIn('private', str(error.exception))
        for status in (True, 199, 207, 400):
            with self.assertRaises(ValueError):
                parse_launcher_token_response(status=status, body=b'{"errorCode":0,"resultData":"x"}')

    def test_http_uses_two_distinct_response_parsers_and_bound_endpoints(self):
        token_plan = plan_nid_launcher_token(credential=NidSdkCredential('provider'), **context())
        token_response = Response(b'{"errorCode":0,"resultData":"launcher-secret"}')
        token = execute_launcher_token(token_plan, expected_url=token_plan.url, _open=lambda *a, **k: token_response)
        self.assertTrue(token_response.closed)
        sign_in = plan_launcher_sign_in(launcher_token=token, **context())
        calls = []
        def open(request, timeout):
            calls.append(request)
            self.assertEqual(request.get_header('Launchertoken'), 'launcher-secret')
            self.assertNotIn(b'launcher-secret', request.data)
            return Response(BODY)
        data = execute_launcher_sign_in(sign_in, expected_url=sign_in.url, _open=open)
        self.assertEqual(data.access_token, 'sdk-token-fixture')
        self.assertEqual(len(calls), 1)
        for executor, wrong_plan in ((execute_launcher_token, sign_in), (execute_launcher_sign_in, token_plan)):
            opener = Mock()
            with self.assertRaises(ValueError): executor(wrong_plan, expected_url=wrong_plan.url, _open=opener)
            opener.assert_not_called()
        response = Response(b'{"errorCode":0,"resultData":"launcher-secret"}')
        with self.assertRaises(SdkSignInHttpError) as error:
            execute_launcher_sign_in(sign_in, expected_url=sign_in.url, _open=lambda *a, **k: response)
        self.assertEqual(error.exception.kind, 'sdk_response_rejected')
        self.assertNotIn('launcher-secret', str(error.exception))

    def test_invalid_identity_or_header_never_becomes_a_request(self):
        for changes in (dict(device_key=''), dict(country_code='jp'), dict(build_code=True),
                        dict(constants={'authUrl': 'http://sdk.invalid'}), dict(existing_sdk_token='private\nvalue')):
            with self.assertRaises(ValueError):
                plan_launcher_sign_in(launcher_token=LauncherToken('x'), **dict(context(), **changes))
        for token in ('', 'private\r\nInjected: yes', 'x' * 8193, None):
            with self.assertRaises(ValueError): plan_launcher_sign_in(launcher_token=LauncherToken(token), **context())
        with self.assertRaises(ValueError):
            plan_nid_launcher_token(credential=LauncherToken('x'), **context())


class LauncherFlowRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        nid_fixtures.NidSdkRunnerTests.setUpClass()
        cls.fixture = nid_fixtures.NidSdkRunnerTests

    def test_explicit_flow_uses_same_device_route_and_only_final_sdk_result(self):
        fixture, calls, phases = self.fixture, [], []
        inputs = (fixture.binding, dict(fixture.profile, country_code='JP'), fixture.constants)
        def token(plan, **kwargs):
            calls.append(plan.url)
            body = json.loads(plan.body)
            self.assertEqual(body['credential']['channelCode'], 33)
            self.assertEqual(body['deviceKey'], fixture.binding.device_key)
            self.assertEqual(body['countryCode'], 'JP')
            self.assertEqual(kwargs['route'], fixture.runner.SocksRoute(17948))
            return LauncherToken('opaque-launcher-fixture')
        def sign_in(plan, **kwargs):
            calls.append(plan.url)
            self.assertEqual(dict(plan.headers)['launcherToken'], 'opaque-launcher-fixture')
            self.assertEqual(json.loads(plan.body)['deviceKey'], fixture.binding.device_key)
            self.assertEqual(kwargs['route'], fixture.runner.SocksRoute(17948))
            return 'final-sdk-result-fixture'
        with patch.object(fixture.runner, 'load_inputs', return_value=inputs):
            result = fixture.runner.run('test@example.invalid', socks_port=17948, auth_flow='launcher',
                _capture=lambda *a, **k: fixture.provider, _execute_token=token, _execute=sign_in, _progress=phases.append)
        self.assertEqual(result, 'final-sdk-result-fixture')
        self.assertEqual(calls, ['https://sdk.example.invalid/launcher/token', 'https://sdk.example.invalid/launcher/sign-in'])
        self.assertEqual(phases, ['sdk_launcher_token', 'sdk_launcher_sign_in'])

    def test_failure_stops_flow_without_fallback_or_creation(self):
        fixture = self.fixture
        with patch.object(fixture.runner, 'load_inputs', return_value=(fixture.binding, fixture.profile, fixture.constants)):
            final = Mock()
            with self.assertRaises(SdkSignInHttpError):
                fixture.runner.run('test@example.invalid', auth_flow='launcher', _capture=lambda *a, **k: fixture.provider,
                    _execute_token=Mock(side_effect=SdkSignInHttpError('sdk_response_rejected')), _execute=final)
            final.assert_not_called()
        with patch.object(fixture.runner, 'load_inputs') as load:
            with self.assertRaises(ValueError):
                fixture.runner.run('test@example.invalid', auth_flow='launcher', create_sdk_player=True)
            load.assert_not_called()


if __name__ == '__main__':
    unittest.main()
