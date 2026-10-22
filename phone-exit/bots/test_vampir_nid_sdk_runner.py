import importlib.util
import json
import hashlib
from pathlib import Path
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit
from vampir_test_sources import historical_exe_reads


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

    def test_launcher_login_and_explicit_signup_share_the_same_nid_request(self):
        from vampir_core.sdk_launcher_auth import LauncherToken
        captures, endpoints = [], []
        def capture(plan, **kwargs):
            captures.append((plan.url, kwargs))
            return self.provider
        def execute(plan, **kwargs):
            endpoints.append(urlsplit(plan.url).path)
            return 'accepted-fixture'
        def token(plan, **kwargs):
            endpoints.append(urlsplit(plan.url).path)
            return LauncherToken('launcher-token-fixture')
        with patch.object(self.runner, 'load_inputs', return_value=(self.binding, self.profile, self.constants)):
            self.runner.run('test@example.invalid', password='password-fixture', auth_flow='launcher',
                _capture=capture, _execute=execute, _execute_token=token)
            self.runner.run('test@example.invalid', password='password-fixture', auth_flow='nid', create_sdk_player=True,
                _capture=capture, _execute=execute, _execute_token=token)
        self.assertEqual(captures[0], captures[1])
        self.assertEqual(endpoints, ['/launcher/token', '/launcher/sign-in', '/v1/sign-up'])

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
        with historical_exe_reads(stored['source'],stored['source_sha256']):
            self.assertEqual(tool.build(), stored)
        self.assertFalse(stored['active_runtime_settings_verified'])
        self.assertEqual((stored['profile']['os_type'], stored['profile']['game_code']), ('PC', 'thered'))

    def test_sdk_player_creation_is_explicit_and_does_not_retry_sign_in(self):
        calls = []
        def execute(plan, **kwargs):
            calls.append(plan.url)
            self.assertEqual(kwargs['expected_url'], 'https://sdk.example.invalid/v1/sign-up')
            self.assertNotIn('playerId', json.loads(plan.body))
            return 'registered-fixture'
        with patch.object(self.runner, 'load_inputs', return_value=(self.binding, self.profile, self.constants)):
            result = self.runner.run('test@example.invalid', create_sdk_player=True,
                _capture=lambda *a, **k: self.provider, _execute=execute)
        self.assertEqual(result, 'registered-fixture')
        self.assertEqual(calls, ['https://sdk.example.invalid/v1/sign-up'])

    def test_browser_and_sdk_share_route_and_observed_country(self):
        calls = []
        profile = dict(self.profile, country_code='HK')
        def capture(plan, **kwargs):
            self.assertEqual(kwargs['socks_port'], 17948)
            self.assertEqual(parse_qs(urlsplit(plan.url).query)['countryCode'], ['HK'])
            self.assertIn('socks-17948', str(kwargs['data_directory']))
            calls.append('browser')
            return self.provider  # Fixture account joined KR, unlike current route HK.
        def execute(plan, **kwargs):
            self.assertEqual(kwargs['route'], self.runner.SocksRoute(17948))
            self.assertEqual(json.loads(plan.body)['countryCode'], 'HK')
            calls.append('sdk')
            return 'accepted-fixture'
        with patch.object(self.runner, 'load_inputs', return_value=(self.binding, profile, self.constants)) as load:
            result = self.runner.run('test@example.invalid', socks_port=17948, _capture=capture, _execute=execute)
        self.assertEqual(result, 'accepted-fixture')
        self.assertEqual(calls, ['browser', 'sdk'])
        load.assert_called_once_with('test@example.invalid', route=self.runner.SocksRoute(17948), selected_profile='recovered-base')

    def test_real_hk_snapshot_route_binding_and_country(self):
        root = Path('F:/PhoneExit Resources/Vampir')
        folder = root / 'public-gmc2-snapshots/070408d4d6fff16f5b7fe4c95aaaa8f9fdbef4ac5f4d958f1475655b4d5c747a'
        manifest = (folder / 'manifest.json').read_bytes()
        self.assertEqual(hashlib.sha256(manifest).hexdigest(), folder.name)
        with tempfile.TemporaryDirectory() as temp:
            temp_root = Path(temp)
            (temp_root / 'code-clues').mkdir()
            profile = (root / 'code-clues/nid-windows-initial-profile.json').read_bytes()
            (temp_root / 'code-clues/nid-windows-initial-profile.json').write_bytes(profile)
            (temp_root / 'manifest.json').write_bytes(manifest)
            (temp_root / 'body.bin').write_bytes((folder / 'body.bin').read_bytes())
            (temp_root / 'code-clues/public-gmc2-recovery.json').write_text(json.dumps(
                dict(manifest=str(temp_root / 'manifest.json'), sha256=folder.name)), encoding='utf-8')
            identity = SimpleNamespace(device_key=self.binding.device_key, nid_device_key=self.binding.nid_device_key,
                                       nm_device_key=self.binding.nm_device_key)
            source_profile=json.loads(profile)
            with historical_exe_reads(source_profile['source'],source_profile['source_sha256']), \
                    patch.object(self.runner, 'ROOT', temp_root), \
                    patch.object(self.runner, 'DeviceRegistry') as registry, \
                    patch.object(self.runner, 'observe_windows_device_identity', return_value=identity), \
                    patch.object(self.runner, 'observe_windows_version') as observe_version:
                from vampir_core.windows_version import WindowsVersion
                observe_version.return_value = WindowsVersion(10, 0, 26200, 1, 256)
                registry.return_value.get.return_value = self.binding
                binding, profile, constants = self.runner.load_inputs('fixture@example.invalid', route=self.runner.SocksRoute(17948))
                self.assertEqual(profile['country_code'], 'HK')
                self.assertEqual(profile['os_version'], '10.0.26200.1.256.64bit')
                self.assertTrue(constants)
                observe_version.return_value = None
                _, failed_profile, _ = self.runner.load_inputs('fixture@example.invalid', route=self.runner.SocksRoute(17948))
                self.assertEqual(failed_profile['os_version'], '')
                for wrong in (None, self.runner.SocksRoute(17949)):
                    with self.assertRaisesRegex(ValueError, 'snapshot route differs'):
                        self.runner.load_inputs('fixture@example.invalid', route=wrong)


if __name__ == '__main__': unittest.main()
