import importlib.util
import json
import io
from email.message import Message
from pathlib import Path
import sys
import unittest
from dataclasses import replace

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.nid_sdk_credential import NidSdkCredential
from vampir_core.sdk_sign_in import plan_nid_sdk_sign_up
from vampir_core.sdk_sign_in_http import execute_sdk_sign_in, execute_sdk_sign_up
from vampir_core.sdk_sign_up_response import parse_sdk_sign_up_response


class SdkSignUpTests(unittest.TestCase):
    def test_registration_result_is_not_a_sign_in_token(self):
        body = b'{"errorCode":0,"resultData":{"playerInfo":{"player":{"playerId":"new-player-fixture"}}}}'
        data = parse_sdk_sign_up_response(status=200, body=body)
        self.assertEqual(data.player_id, 'new-player-fixture')
        self.assertFalse(hasattr(data, 'access_token'))
        self.assertNotIn('new-player-fixture', repr(data))
        for bad in (b'{"errorCode":0}', body.replace(b'"new-player-fixture"', b'""'),
                    body.replace(b'"errorCode":0', b'"errorCode":1203'),
                    body.replace(b'"errorCode":0', b'"errorCode":false'),
                    body.replace(b'"errorCode":0', b'"errorCode":0,"errorCode":0')):
            with self.assertRaises(ValueError): parse_sdk_sign_up_response(status=200, body=bad)
        with self.assertRaises(ValueError): parse_sdk_sign_up_response(status=400, body=body)

    def test_one_registration_post_requires_valid_player_result(self):
        plan = plan_nid_sdk_sign_up(constants={'authUrl':'https://sdk.example.invalid'},
            credential=NidSdkCredential('fixture-token'), game_code='thered', build_code=0,
            nm_device_key='nm-fixture', device_key='device-fixture', country_code='UA', os_type='PC')
        response = io.BytesIO(b'{"errorCode":0,"resultData":{"playerInfo":{"player":{"playerId":"new-player-fixture"}}}}')
        response.status = 200
        response.headers = Message()
        calls = []
        def open(request, timeout):
            calls.append(request)
            self.assertEqual(request.full_url, 'https://sdk.example.invalid/v1/sign-up')
            self.assertEqual(request.method, 'POST')
            return response
        data = execute_sdk_sign_up(plan, expected_url=plan.url, _open=open)
        self.assertEqual(data.player_id, 'new-player-fixture')
        self.assertEqual(len(calls), 1)
        self.assertTrue(response.closed)

    def test_creation_requires_separate_transport_entry(self):
        plan = plan_nid_sdk_sign_up(constants={'authUrl':'https://sdk.example.invalid'},
            credential=NidSdkCredential('fixture-token'), game_code='thered', build_code=0,
            nm_device_key='nm-fixture', device_key='device-fixture', country_code='UA', os_type='PC')
        def forbidden(*args, **kwargs): self.fail('Wrong operation reached network')
        with self.assertRaises(ValueError):
            execute_sdk_sign_in(plan, expected_url=plan.url, _open=forbidden)
        signin = replace(plan, url=plan.url.replace('/v1/sign-up', '/v1/sign-in'))
        with self.assertRaises(ValueError):
            execute_sdk_sign_up(signin, expected_url=signin.url, _open=forbidden)

    def test_native_replay_and_explicit_plan(self):
        path = HERE / 'resource-tools/vampir/replay-sdk-sign-up-body.py'
        spec = importlib.util.spec_from_file_location('signup_replay_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        stored = Path('F:/PhoneExit Resources/Vampir/code-clues/sdk-sign-up-body-replay.json')
        original = stored.read_bytes()
        baseline = json.loads(original)
        snapshot = tool.ROOT / 'client-code-snapshots' / baseline['sha256'] / 'ProjectRED-Win64-Shipping.exe'
        result = tool.build(source_snapshot=snapshot)
        # Historical execution is explicit and SHA-checked, never evidence for the installed release.
        for field in ('sha256', 'segments', 'fragments', 'literals', 'cases', 'network_ready', 'limitations'):
            self.assertEqual(baseline[field], result[field], field)
        self.assertEqual(result['source'], str(snapshot))
        self.assertEqual(stored.read_bytes(), original)
        self.assertEqual([x['text'] for x in result['literals']], ['authUrl', 'v1/sign-up'])
        self.assertEqual(len(result['cases']), 4)
        for case in result['cases']:
            f = case['fixture']
            if not f['credential']: continue
            plan = plan_nid_sdk_sign_up(constants={'authUrl':'https://sdk.example.invalid'},
                credential=NidSdkCredential(f['credential']['channelAccessToken']), game_code='thered', build_code=0,
                nm_device_key=f['nmDeviceKey'], device_key=f['deviceKey'], country_code=f['countryCode'], os_type=f['os'])
            self.assertEqual(plan.url, 'https://sdk.example.invalid/v1/sign-up')
            self.assertEqual(json.loads(plan.body), case['body'])
            self.assertNotIn('playerId', json.loads(plan.body))
            self.assertNotIn('accessToken', dict(plan.headers))
            self.assertNotIn(f['credential']['channelAccessToken'], repr(plan))

    def test_wrong_snapshot_is_rejected_without_changing_historical_report(self):
        import tempfile
        spec = importlib.util.spec_from_file_location('signup_snapshot_gate', HERE / 'resource-tools/vampir/replay-sdk-sign-up-body.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        stored = tool.ROOT / 'code-clues/sdk-sign-up-body-replay.json'
        before = stored.read_bytes()
        with tempfile.TemporaryDirectory() as folder:
            bad = Path(folder) / 'bad.exe'; bad.write_bytes(b'wrong-source-fixture')
            with self.assertRaisesRegex(ValueError, 'Installed client changed'):
                tool.build(source_snapshot=bad)
        self.assertEqual(stored.read_bytes(), before)


if __name__ == '__main__': unittest.main()
