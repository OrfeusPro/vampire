"""Current pinned SDK inputs through both launcher plans, with no external IO."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CurrentSdkRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = load('current_sdk_runtime_runner', HERE / 'vampir-headless/run-nid-sdk-sign-in.py')
        cls.builder = load('current_sdk_runtime_builder', HERE / 'resource-tools/vampir/build-sdk-runtime-profile-11316.py')
        cls.loader = load('current_sdk_runtime_loader', HERE / 'vampir-headless/sdk-source-profile.py')
        from vampir_core.device_registry import DeviceBinding
        from vampir_core.nid_result import NidEmailCredential
        cls.binding = DeviceBinding('fixture@example.invalid', 'fixture-profile', 'real', True,
            'sdk-fixture', 'nm-fixture', 'fixture-source', 'unknown', '', 'nid-fixture', 'fixture-nid-source')
        cls.provider = NidEmailCredential('provider-fixture', '', 'nid-account-fixture', 'HK')
        # Empty secret list is valid; the real XOR and envelope decoders run.
        key = 'fixture-key'
        def encrypt(value):
            raw = json.dumps(value).encode('utf-16le')
            units = struct.unpack('<' + 'H' * (len(raw) // 2), raw)
            return struct.pack('<' + 'H' * len(units),
                *(unit ^ ord(key[i % len(key)]) for i, unit in enumerate(units))).decode('utf-16le')
        cls.body = json.dumps(dict(errorCode=0, resultData=dict(
            encConstants=encrypt(dict(authWebViewUrl='https://members.netmarble.com/auth',
                authUrl='https://sdk.example.invalid')), encSecretConstants=encrypt([]),
            geoIp=dict(clientIp='1.1.1.1', geoLocation='JP', isoCountry='HK')))).encode()
        cls.transport = dict(status=200, tls_certificate_verification=True,
            socks5_loopback_port=17948, headers=[('DECKEY', key)])
        cls.profile = cls.builder.build()

    def prepared(self):
        binding = self.binding
        identity = SimpleNamespace(device_key=binding.device_key, nid_device_key=binding.nid_device_key,
            nm_device_key=binding.nm_device_key)
        with patch.object(self.runner, 'DeviceRegistry') as registry, \
                patch.object(self.runner, 'observe_windows_device_identity', return_value=identity), \
                patch.object(self.runner, 'observe_windows_version', return_value=None), \
                patch.object(self.runner, 'fetch_gmc2', return_value=(self.body, self.transport)) as fetch, \
                patch.object(self.runner.time, 'monotonic', return_value=100):
            registry.return_value.get.return_value = binding
            result = self.runner.load_inputs(binding.email, route=self.runner.SocksRoute(17948),
                selected_profile='recovered-release')
        fetch.assert_called_once()
        self.assertEqual(result.source_sha256, self.profile['source_sha256'])
        self.assertEqual(result.geo.body_sha256, hashlib.sha256(self.body).hexdigest())
        self.assertEqual(result.profile['country_code'], 'HK')
        return result

    def run_prepared(self, prepared, **kwargs):
        return self.runner.run(prepared.email, selected_profile='recovered-release', socks_port=17948,
            auth_flow='launcher', _prepared_inputs=prepared, **kwargs)

    def test_builder_reproduces_pinned_manifest_and_declares_limits(self):
        raw = (self.runner.ROOT / 'sdk-source-profiles' / self.loader.RELEASE_PROFILE_SHA / 'manifest.json').read_bytes()
        self.assertEqual(json.loads(raw), self.profile)
        self.assertEqual(self.profile['supported_auth_flows'], ['launcher'])
        for key in ('network_ready', 'game_protocol_verified', 'direct_sdk_operations_verified'):
            self.assertIs(self.profile[key], False)

    def test_complete_offline_launcher_path_keeps_credentials_and_device_keys_separate(self):
        from vampir_core.sdk_launcher_auth import LauncherToken
        prepared = self.prepared()
        capture = Mock(return_value=self.provider)
        token = Mock(return_value=LauncherToken('launcher-fixture'))
        execute = Mock(return_value='synthetic-accepted')
        with patch.object(self.runner.time, 'monotonic', return_value=100):
            result = self.run_prepared(prepared, _capture=capture, _execute_token=token, _execute=execute)
        self.assertEqual(result, 'synthetic-accepted')
        first = token.call_args.args[0]
        second = execute.call_args.args[0]
        self.assertTrue(first.url.endswith('/launcher/token'))
        self.assertTrue(second.url.endswith('/launcher/sign-in'))
        first_body, second_body = json.loads(first.body), json.loads(second.body)
        self.assertIn('credential', first_body)
        self.assertNotIn('credential', second_body)
        self.assertEqual(dict(second.headers)['launcherToken'], 'launcher-fixture')
        self.assertNotIn('launcherToken', dict(first.headers))
        self.assertEqual(second_body['deviceKey'], 'sdk-fixture')
        self.assertIn('nid-fixture', capture.call_args.args[0].url)
        for call in (token.call_args, execute.call_args):
            self.assertEqual(call.kwargs['route'].port, 17948)
        self.assertNotIn('provider-fixture', repr(first))
        self.assertNotIn('launcher-fixture', repr(second))

    def test_token_delay_expires_context_before_second_post(self):
        from vampir_core.sdk_launcher_auth import LauncherToken
        prepared = self.prepared()
        execute = Mock()
        with patch.object(self.runner.time, 'monotonic', return_value=100) as clock:
            def token(*args, **kwargs):
                clock.return_value = 401
                return LauncherToken('launcher-fixture')
            with self.assertRaisesRegex(ValueError, 'expired'):
                self.run_prepared(prepared, _capture=lambda *a, **k: self.provider,
                    _execute_token=token, _execute=execute)
        execute.assert_not_called()

    def test_unported_operations_reject_before_browser(self):
        prepared = self.prepared()
        capture, execute = Mock(), Mock()
        for options in ({}, dict(fetch_player=True), dict(create_sdk_player=True), dict(first_sdk_login=True)):
            with self.subTest(options=options), patch.object(self.runner.time, 'monotonic', return_value=100):
                with self.assertRaisesRegex(ValueError, 'launcher sign-in only'):
                    self.runner.run(prepared.email, selected_profile='recovered-release', socks_port=17948,
                        _prepared_inputs=prepared, _capture=capture, _execute=execute, **options)
        capture.assert_not_called()
        execute.assert_not_called()

    def test_corrupt_auth_report_rejects_profile_build(self):
        original = self.builder.digest
        def corrupt(path):
            if 'nid-primitives-11316' in str(path):
                return '0' * 64
            return original(path)
        with patch.object(self.builder, 'digest', side_effect=corrupt):
            with self.assertRaisesRegex(ValueError, 'report changed'):
                self.builder.build()

    def test_changed_report_dependency_rejects_profile_build(self):
        original = self.builder.digest
        def corrupt(path):
            if Path(path).name == 'replay-nid-context-11316.py':
                return '0' * 64
            return original(path)
        with patch.object(self.builder, 'digest', side_effect=corrupt):
            with self.assertRaisesRegex(ValueError, 'dependency changed'):
                self.builder.build()


if __name__ == '__main__':
    unittest.main()
