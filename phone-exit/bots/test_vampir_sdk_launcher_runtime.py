"""Seven offline SDK Launcher composition cases with explicit immutable inputs."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
TOOLS = HERE / 'resource-tools/vampir'
sys.path.insert(0, str(HERE / 'vampir-shared'))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SdkLauncherRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = load('sdk_launcher_runtime_builder', TOOLS / 'build-sdk-launcher-profile.py')
        cls.loader = load('sdk_launcher_runtime_loader', HERE / 'vampir-headless/sdk-launcher-profile.py')
        cls.runner = load('sdk_launcher_runtime_runner', HERE / 'vampir-headless/run-nid-sdk-sign-in.py')
        cls.profile = cls.builder.build()
        cls.manifest = cls.builder.publish(cls.profile)
        cls.options = dict(profile_sha256=cls.manifest.parent.name,
                           source_sha256=cls.profile['source_sha256'])
        from vampir_core.device_registry import DeviceBinding
        from vampir_core.nid_result import NidEmailCredential
        cls.binding = DeviceBinding('fixture@example.invalid', 'fixture-profile', 'real', True,
            'sdk-fixture', 'nm-fixture', 'fixture-source', 'unknown', '', 'nid-fixture', 'fixture-nid-source')
        cls.provider = NidEmailCredential('provider-fixture', '', 'nid-account-fixture', 'HK')
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

    @contextmanager
    def composition_fixture(self):
        # The existing runner has no standalone SDK selector. Only its dynamic
        # profile-loader boundary is substituted in this fixture. The new
        # loader still checks the explicit profile and every real pinned input.
        util = self.runner.importlib.util
        original_spec, original_module = util.spec_from_file_location, util.module_from_spec
        sentinel = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
        fixture_loader = SimpleNamespace(load_release_profile=lambda kind, **kwargs:
            self.loader.load_profile(kind, **self.options, **kwargs))

        def selected_spec(name, path, *args, **kwargs):
            if name == 'nid_release_source':
                return sentinel
            return original_spec(name, path, *args, **kwargs)

        def selected_module(spec):
            return fixture_loader if spec is sentinel else original_module(spec)

        from vampir_core import gmc2_context
        # This test permission names one current SHA and one existing SDK
        # policy. No persistent admission, release bundle or world permission
        # is installed. Actual runtime rejects this unbound source afterward.
        with patch.object(util, 'spec_from_file_location', side_effect=selected_spec), \
                patch.object(util, 'module_from_spec', side_effect=selected_module), \
                patch.object(gmc2_context, 'permits', side_effect=lambda sha, policy:
                    sha == self.profile['source_sha256'] and policy == 'sdk-launcher-gmc2-geo-v2'):
            yield

    def prepared(self):
        identity = SimpleNamespace(device_key=self.binding.device_key, nid_device_key=self.binding.nid_device_key,
                                   nm_device_key=self.binding.nm_device_key)
        with patch.object(self.runner, 'DeviceRegistry') as registry, \
                patch.object(self.runner, 'observe_windows_device_identity', return_value=identity), \
                patch.object(self.runner, 'observe_windows_version', return_value=None), \
                patch.object(self.runner, 'fetch_gmc2', return_value=(self.body, self.transport)) as fetch, \
                patch.object(self.runner.time, 'monotonic', return_value=100):
            registry.return_value.get.return_value = self.binding
            result = self.runner.load_inputs(self.binding.email, route=self.runner.SocksRoute(17948),
                                             selected_profile='recovered-release')
        fetch.assert_called_once()
        self.assertEqual(result.source_sha256, self.profile['source_sha256'])
        self.assertEqual(result.geo.body_sha256, hashlib.sha256(self.body).hexdigest())
        self.assertEqual(result.profile['country_code'], 'HK')
        return result

    def run_prepared(self, prepared, **kwargs):
        return self.runner.run(prepared.email, selected_profile='recovered-release', socks_port=17948,
                               auth_flow='launcher', _prepared_inputs=prepared, **kwargs)

    def test_builder_reproduces_manifest_and_explicit_loader_declares_limits(self):
        original = self.builder.load
        native_runs = []
        def checked_loader(name, path=None):
            if name == 'audit-launcher-contract':
                raise AssertionError('Ready Launcher proof must be reused')
            module = original(name, path)
            if name == 'sdk-batch-runner':
                module.run = Mock(side_effect=AssertionError('Ready SDK native proof must be reused'))
                native_runs.append(module.run)
            return module
        with patch.object(self.builder, 'load', side_effect=checked_loader):
            self.assertEqual(self.builder.build(), self.profile)
        self.assertEqual(len(native_runs), 1)
        native_runs[0].assert_not_called()
        self.assertEqual(json.loads(self.manifest.read_bytes()), self.profile)
        self.assertEqual(self.profile['supported_auth_flows'], ['launcher'])
        for key in ('network_ready', 'game_protocol_verified', 'direct_sdk_operations_verified', 'runtime_admitted'):
            self.assertIs(self.profile[key], False)
        for kind in ('nid', 'public_gmc2'):
            section = self.loader.load_profile(kind, **self.options)
            self.assertEqual(section['source_sha256'], self.profile['source_sha256'])
            self.assertEqual(section['profile_sha256'], self.manifest.parent.name)
            self.assertEqual(section['profile'], self.profile[kind]['profile'])
        from vampir_core.gmc2_context import decode_gmc2_geo
        with self.assertRaisesRegex(ValueError, 'not verified'):
            decode_gmc2_geo(self.body, source_sha256=self.profile['source_sha256'])

    def test_complete_offline_launcher_path_keeps_credentials_and_device_keys_separate(self):
        from vampir_core.sdk_launcher_auth import LauncherToken
        with self.composition_fixture():
            prepared = self.prepared()
            capture = Mock(return_value=self.provider)
            token = Mock(return_value=LauncherToken('launcher-fixture'))
            execute = Mock(return_value='synthetic-accepted')
            with patch.object(self.runner.time, 'monotonic', return_value=100):
                result = self.run_prepared(prepared, _capture=capture, _execute_token=token, _execute=execute)
        self.assertEqual(result, 'synthetic-accepted')
        first, second = token.call_args.args[0], execute.call_args.args[0]
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
        with self.composition_fixture():
            prepared = self.prepared()
            execute = Mock()
            with patch.object(self.runner.time, 'monotonic', return_value=100) as clock:
                def token(*args, **kwargs):
                    clock.return_value = 401
                    return LauncherToken('launcher-fixture')
                with self.assertRaisesRegex(ValueError, 'expired'):
                    self.run_prepared(prepared, _capture=lambda *args, **kwargs: self.provider,
                                      _execute_token=token, _execute=execute)
            execute.assert_not_called()

    def test_unported_operations_reject_before_browser(self):
        with self.composition_fixture():
            prepared = self.prepared()
            capture, execute = Mock(), Mock()
            for options in ({}, dict(fetch_player=True), dict(create_sdk_player=True), dict(first_sdk_login=True)):
                with self.subTest(options=options), patch.object(self.runner.time, 'monotonic', return_value=100):
                    with self.assertRaisesRegex(ValueError, 'launcher sign-in only'):
                        self.runner.run(prepared.email, selected_profile='recovered-release', socks_port=17948,
                            _prepared_inputs=prepared, _capture=capture, _execute=execute, **options)
            capture.assert_not_called()
            execute.assert_not_called()

    def test_changed_installed_source_rejects_profile_build(self):
        original = self.builder.digest
        def corrupt(path):
            return '0' * 64 if Path(path).resolve() == self.builder.INSTALLED.resolve() else original(path)
        with patch.object(self.builder, 'digest', side_effect=corrupt):
            with self.assertRaisesRegex(ValueError, 'Installed SDK source differs'):
                self.builder.build()

    def test_changed_component_context_or_path_rejects(self):
        original = self.builder.digest
        def corrupt(path):
            return '0' * 64 if 'code-clues' in Path(path).parts else original(path)
        with patch.object(self.builder, 'digest', side_effect=corrupt):
            with self.assertRaisesRegex(ValueError, 'component report changed'):
                self.builder.build()
        original = self.loader.digest
        context = self.profile['evidence']['launcher_context']['path']
        def changed_context(path, budget):
            return '0' * 64 if Path(path).resolve() == Path(context).resolve() else original(path, budget)
        with patch.object(self.loader, 'digest', side_effect=changed_context):
            with self.assertRaisesRegex(ValueError, 'dependency changed'):
                self.loader.load_profile('nid', **self.options)
        with self.assertRaisesRegex(ValueError, 'outside allowed paths'):
            self.loader.input_budget(self.loader.WORKSPACE.parent / 'outside.txt', root=self.loader.ROOT,
                                     workspace=self.loader.WORKSPACE, installed=self.loader.INSTALLED)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'fixture.bin'
            path.write_bytes(b'oversized fixture')
            with self.assertRaisesRegex(ValueError, 'content budget'):
                self.loader.digest(path, 1)
        incomplete = dict(self.profile, evidence=dict(self.profile['evidence'], components={}))
        with self.assertRaisesRegex(ValueError, 'evidence set differs'):
            self.loader.validate_evidence(incomplete, self.loader.ROOT, self.loader.WORKSPACE)

    def test_changed_manifest_rejects_loader(self):
        original = Path.read_bytes
        def corrupt(path):
            raw = original(path)
            return raw + b' ' if path == self.manifest else raw
        with patch.object(Path, 'read_bytes', side_effect=corrupt, autospec=True):
            with self.assertRaisesRegex(ValueError, 'profile changed'):
                self.loader.load_profile('nid', **self.options)
        with self.assertRaisesRegex(ValueError, 'explicit full'):
            self.loader.load_profile('nid', profile_sha256='../invalid', source_sha256=self.profile['source_sha256'])


if __name__ == '__main__':
    unittest.main()
