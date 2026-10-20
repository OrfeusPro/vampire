import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit


class NidSdkRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'vampir-headless/run-nid-sdk-sign-in.py'
        spec = importlib.util.spec_from_file_location('nid_sdk_runner_test', path)
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)
        from vampir_core.device_registry import DeviceBinding
        from vampir_core.nid_result import NidEmailCredential
        cls.binding = DeviceBinding('test@example.invalid', 'fixture-profile', 'real', True,
            'sdk-key-fixture', 'nm-key-fixture', 'fixture-source', 'unknown', '', 'nid-key-fixture', 'fixture-nid-source')
        cls.provider = NidEmailCredential('provider-fixture', '', 'nid-account-fixture', 'KR')
        cls.profile = dict(game_code='thered', client_id='client-fixture', build_code=0, os_type='PC',
            raw_webview_type=0, country_code='', language='en', os_version='')
        cls.constants = dict(authWebViewUrl='https://members.netmarble.com/auth', authUrl='https://sdk.example.invalid')

    def test_one_browser_result_becomes_one_sdk_request_with_separate_keys(self):
        calls = []
        def capture(plan, **kwargs):
            values = parse_qs(urlsplit(plan.url).query)
            self.assertEqual(values['deviceKey'], ['nid-key-fixture'])
            self.assertEqual(kwargs['expected_email'], 'test@example.invalid')
            calls.append('browser')
            return self.provider
        def execute(plan, **kwargs):
            body = json.loads(plan.body)
            self.assertEqual(body['deviceKey'], 'sdk-key-fixture')
            self.assertEqual(body['credential'], dict(channelCode=33, channelAccessToken='provider-fixture'))
            self.assertEqual(body['countryCode'], 'KR')
            self.assertNotIn('accessToken', dict(plan.headers))
            self.assertEqual(kwargs['expected_url'], 'https://sdk.example.invalid/v1/sign-in')
            calls.append('sdk')
            return 'accepted-fixture'
        with patch.object(self.runner, 'load_inputs', return_value=(self.binding, self.profile, self.constants)):
            result = self.runner.run('test@example.invalid', _capture=capture, _execute=execute)
        self.assertEqual((result, calls), ('accepted-fixture', ['browser', 'sdk']))

    def test_browser_failure_and_required_confirmation_prevent_sdk_post(self):
        for required in (False, True):
            binding = replace(self.binding, confirmation='required') if required else self.binding
            with patch.object(self.runner, 'load_inputs', return_value=(binding, self.profile, self.constants)), \
                    patch.object(self.runner, 'execute_sdk_sign_in'):
                with self.assertRaises((PermissionError, RuntimeError)):
                    self.runner.run('test@example.invalid', _capture=lambda *a, **k: (_ for _ in ()).throw(RuntimeError('cancelled')),
                                    _execute=lambda *a, **k: self.fail('POST must not run'))

    def test_source_profile_reproduces_without_native_cache_claim(self):
        path = Path(__file__).parent / 'resource-tools/vampir/build-nid-windows-profile.py'
        spec = importlib.util.spec_from_file_location('nid_windows_profile_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        stored = json.loads((tool.ROOT / 'code-clues/nid-windows-initial-profile.json').read_text('utf-8'))
        self.assertEqual(tool.build(), stored)
        self.assertFalse(stored['active_runtime_settings_verified'])
        self.assertEqual((stored['profile']['os_type'], stored['profile']['game_code']), ('PC', 'thered'))


if __name__ == '__main__': unittest.main()
