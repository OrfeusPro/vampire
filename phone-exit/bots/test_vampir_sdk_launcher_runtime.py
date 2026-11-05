"""SDK Launcher composition and isolated, explicit immutable runtime scope."""
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
        from vampir_core.sdk_launcher_admission import scope
        # Exercise the actual selector and integrity guard. Only external IO
        # below is synthetic; profile loading and policy admission are real.
        with scope(self.selector, root=self.loader.ROOT, workspace=self.loader.WORKSPACE):
            yield

    @property
    def selector(self):
        return 'sdk-launcher:' + self.manifest.parent.name

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
                                             selected_profile=self.selector)
        fetch.assert_called_once()
        self.assertEqual(result.source_sha256, self.profile['source_sha256'])
        self.assertEqual(result.geo.body_sha256, hashlib.sha256(self.body).hexdigest())
        self.assertEqual(result.profile['country_code'], 'HK')
        return result

    def run_prepared(self, prepared, **kwargs):
        return self.runner.run(prepared.email, selected_profile=self.selector, socks_port=17948,
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
                    with self.assertRaisesRegex(ValueError, 'supports launcher sign-in'):
                        self.runner.run(prepared.email, selected_profile=self.selector, socks_port=17948,
                            _prepared_inputs=prepared, _capture=capture, _execute=execute, **options)
            capture.assert_not_called()
            execute.assert_not_called()

    def test_scope_is_exact_sdk_only_and_is_removed_on_error(self):
        from vampir_core.sdk_launcher_admission import scope, current, POLICY
        from vampir_core.runtime_admission import permits, POLICIES, current_bundle
        from concurrent.futures import ThreadPoolExecutor
        sha = self.profile['source_sha256']
        self.assertFalse(permits(sha, POLICY))
        with self.assertRaisesRegex(RuntimeError, 'fixture stopped'):
            with self.composition_fixture():
                self.assertTrue(permits(sha, POLICY))
                self.assertFalse(permits('0' * 64, POLICY))
                self.assertIsNone(current_bundle(self.selector))
                for policy in POLICIES - {POLICY}:
                    self.assertFalse(permits(sha, policy), policy)
                with ThreadPoolExecutor(max_workers=1) as workers:
                    self.assertFalse(workers.submit(permits, sha, POLICY).result())
                detached = current(self.selector)
                detached['nid'].clear()
                self.assertTrue(current(self.selector)['nid'])
                with self.assertRaisesRegex(ValueError, 'switch'):
                    with scope('sdk-launcher:' + '0' * 64,
                               root=self.loader.ROOT, workspace=self.loader.WORKSPACE):
                        self.fail('Different profile entered')
                raise RuntimeError('fixture stopped')
        self.assertFalse(permits(sha, POLICY))
        with self.assertRaisesRegex(ValueError, 'explicit admitted scope'):
            current(self.selector)
        with self.assertRaisesRegex(ValueError, 'full immutable'):
            with scope('sdk-launcher:../invalid', root=self.loader.ROOT, workspace=self.loader.WORKSPACE):
                self.fail('Invalid selector entered')
        from vampir_core import runtime_admission as world
        token = world._active.set(SimpleNamespace(source_sha256=sha))
        try:
            with self.assertRaisesRegex(ValueError, 'world worker'):
                with self.composition_fixture():
                    self.fail('SDK-only selector entered a world worker')
        finally:
            world._active.reset(token)

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


class AccountEntryDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load('account_entry_diagnostic_tests', HERE / 'vampir-headless/run-account-entry-diagnostic.py')

    def test_shape_does_not_include_values_or_untrusted_labels(self):
        fields = self.tool.shape({'deviceKey': 'private-device', 'items': [{'token': 'private-token'}],
                                  'invalid label with private data': 'secret'})
        self.assertEqual(fields['$.deviceKey'], 'string')
        self.assertEqual(fields['$.items[].token'], 'string')
        self.assertNotIn('private', json.dumps(fields))
        self.assertNotIn('secret', json.dumps(fields))

    def test_old_account_settings_are_normalized_without_changing_saved_assignment(self):
        from vampir_core.account_store import AccountStore
        store = Mock()
        original = {}
        store.credential.return_value = ('fixture@example.invalid', 'private-password', original)
        factory = Mock(return_value=store)
        factory.assignment = AccountStore.assignment
        runner = Mock()
        runner.run.return_value = SimpleNamespace(player_id='fixture-player', access_token='fixture-token')
        browser = SimpleNamespace(capture_nid_credential=Mock())
        capture = Mock()
        capture.folder = Path('fixture-private')
        capture.finish.side_effect = lambda result: dict(result=result)
        with patch.object(self.tool, 'AccountStore', factory), patch.object(self.tool, 'Capture', return_value=capture), \
                patch.object(self.tool, 'load', side_effect=lambda name: browser if name == 'nid-browser' else runner), \
                patch('builtins.print') as output:
            self.assertTrue(self.tool.run('fixture-account', 'a' * 64))
        self.assertEqual(original, {})
        self.assertIsNone(runner.run.call_args.kwargs['socks_port'])
        self.assertEqual(runner.run.call_args.kwargs['device_settings'], {})
        self.assertNotIn('private-password', str(output.call_args_list))
        self.assertNotIn('fixture-token', str(output.call_args_list))

    def test_private_chunks_use_protection_and_enforce_total_budget(self):
        with tempfile.TemporaryDirectory() as folder:
            calls = []
            def protect(raw):
                calls.append(raw)
                return b'encrypted-fixture'
            capture = self.tool.Capture(Path(folder) / 'capture', protect=protect, limit=90000)
            capture.record('fixture', b'x' * 80000)
            self.assertEqual(len(calls), 2)
            self.assertNotIn(b'x' * 100, (capture.folder / 'sdk-http.dpapi').read_bytes())
            with self.assertRaisesRegex(RuntimeError, 'limit'):
                capture.record('fixture', b'x' * 10001)
            self.assertEqual(len(calls), 2)
            capture.inspect('fixture', b'{"accessToken":"private-fixture"}')
            report = capture.finish(dict(sdk_response_accepted=False))
            self.assertFalse(report['game_session_ready'])
            self.assertNotIn('private-fixture', (capture.folder / 'report.json').read_text())

    def test_sdk_transport_is_unmodified_observed_and_closed(self):
        from io import BytesIO
        from email.message import Message
        from vampir_core.sdk_sign_in import SdkSignInRequestPlan
        from vampir_core.sdk_sign_in_http import execute_launcher_token
        url = 'https://sdk.example.invalid/launcher/token'
        body = b'{"credential":{"channelAccessToken":"private-fixture","channelCode":33}}'
        plan = SdkSignInRequestPlan(url, body, (('Accept', 'application/json'), ('Content-Type', 'application/json')))
        response = BytesIO(b'{"errorCode":0,"resultData":"token-fixture"}')
        response.status, response.headers = 200, Message()
        opener = Mock()
        opener.open.return_value = response
        with tempfile.TemporaryDirectory() as folder:
            capture = self.tool.Capture(Path(folder) / 'capture', protect=lambda raw: b'protected-fixture')
            with patch.object(self.tool.urllib.request, 'build_opener', return_value=opener):
                result = capture.executor('launcher/token', execute_launcher_token)(plan, expected_url=url)
            self.assertEqual(result.value, 'token-fixture')
            opener.open.assert_called_once()
            request = opener.open.call_args.args[0]
            self.assertEqual(request.data, body)
            self.assertEqual(request.full_url, url)
            self.assertTrue(response.closed)
            headers = next(x['fields'] for x in capture.inventory if x['stage'].endswith(':headers'))
            self.assertIn('user-agent', {x.lower() for x in headers})
            self.assertIn('accept-encoding', {x.lower() for x in headers})
            self.assertNotIn('private-fixture', json.dumps(capture.inventory))
            self.assertNotIn('token-fixture', json.dumps(capture.inventory))


class VerificationWebTests(unittest.TestCase):
    def test_nid_failure_uses_fresh_context_and_manual_input_before_any_mail(self):
        tool = load('verify_account_manual_fallback', HERE / 'vampir-headless/verify-account.py')
        class LoginError(RuntimeError):
            browser_status = 'login_failed'
        store = Mock()
        store.credential.return_value = ('fixture@vampir.top', 'saved-password', {})
        runner = Mock()
        first, second = SimpleNamespace(source_sha256='fixture'), SimpleNamespace(source_sha256='fixture')
        runner.load_inputs.side_effect = [first, second]
        def sign_in(email, **kwargs):
            kwargs['_progress']('nid_browser')
            if kwargs['_prepared_inputs'] is first:
                self.assertEqual(kwargs['password'], 'saved-password')
                raise LoginError()
            self.assertIs(kwargs['_prepared_inputs'], second)
            self.assertEqual(kwargs['password'], '')
            self.assertEqual(kwargs['_capture'].keywords, {'bind_manual_email': True})
            return SimpleNamespace(verification_steps=())
        runner.run.side_effect = sign_in
        browser = SimpleNamespace(NidBrowserStatusError=LoginError, capture_nid_credential=Mock())
        calls = []
        def load_fixture(name):
            return {'run-nid-sdk-sign-in': runner, 'nid-browser': browser}[name]
        with patch.object(tool, 'load', side_effect=load_fixture), patch.object(tool, 'scope'), patch.object(tool, 'check_source'):
            self.assertEqual(tool.verify(store, 'fixture', selector='fixture', progress=calls.append), ('verified', []))
        self.assertEqual(calls, ['configuration', 'nid_browser', 'configuration', 'manual_nid_browser'])

    def test_only_explicit_known_sdk_states_schedule_verification(self):
        from vampir_core.sdk_sign_in_response import parse_sdk_sign_in_response
        for state, expected in (
            (dict(deviceSecure=['device-registration'], restriction=['workplace'], withdraw=[]),
             ('device-registration', 'workplace')),
            (dict(deviceSecure=[], restriction=[], withdraw=[]), ()),
            (dict(deviceSecure=[], restriction=['other'], withdraw=[]), None),
            (dict(deviceSecure=[], restriction=[], withdraw=['pending']), None),
            ({}, None),
        ):
            with self.subTest(state=state):
                value = dict(errorCode=0, resultData=dict(accessToken='fixture-token',
                    playerInfo=dict(player=dict(playerId='fixture-player', playerStatus=state))))
                result = parse_sdk_sign_in_response(status=200, body=json.dumps(value).encode())
                self.assertEqual(result.verification_steps, expected)
                self.assertNotIn('fixture-token', repr(result))

    def test_form_urls_use_fresh_sdk_data_and_the_correct_device_key(self):
        from urllib.parse import urlsplit, parse_qs
        tool = load('verify_account_source_tests', HERE / 'vampir-headless/verify-account.py')
        contract = json.loads((tool.KNOWLEDGE / 'verification-web-current.json').read_bytes())
        tool.check_source(contract['source_sha256'])
        with self.assertRaises(ValueError):
            tool.check_source('0' * 64)
        prepared = SimpleNamespace(constants={key: url for key, url in tool.ENDPOINTS.values()},
            profile=dict(game_code='thered', build_code=0, language='en', os_type='windows'),
            geo=SimpleNamespace(iso_country='UA', client_ip='192.0.2.40'),
            binding=SimpleNamespace(device_key='sdk-device', nm_device_key='nm-device', nid_device_key='nid-device'))
        data = SimpleNamespace(access_token='fixture-token', player_id='player', joined_country_code='US')
        for purpose in tool.ENDPOINTS:
            url = tool.web_url(purpose, prepared, data, 'Test & Device')
            parts = urlsplit(url)
            params = parse_qs(parts.query)
            self.assertEqual(parts.hostname, 'profile-auth-view.netmarble.com')
            self.assertEqual(params['deviceName'], ['Test & Device'])
            self.assertEqual(params['accessToken'], ['fixture-token'])
            self.assertEqual(params['countryCode'], ['UA'])
            self.assertEqual(params.get('deviceKey'), ['sdk-device'] if purpose == 'device-registration' else None)
            self.assertNotIn('nid-device', url)
        prepared.constants['deviceWebViewUrl'] = 'https://fixture.invalid/'
        with self.assertRaises(ValueError):
            tool.web_url('device-registration', prepared, data, 'Test Device')


if __name__ == '__main__':
    unittest.main()
