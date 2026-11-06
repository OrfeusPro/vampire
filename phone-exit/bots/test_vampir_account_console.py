import hashlib
import io
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, MagicMock
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.account_store import AccountStore, WindowsVault


class FixtureVault:
    def encrypt(self, value):
        return b'fixture:' + hashlib.sha256(value.encode()).digest()
    def decrypt(self, value):
        raise AssertionError('UI / storage tests must not request a live credential')


class AccountConsoleTests(unittest.TestCase):
    def test_prototype_assets_check_each_retained_file_and_bound_shared_cache(self):
        sys.path.insert(0,str(HERE / 'vampir-headless'))
        import prototype_assets
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();snapshot=root/'maps/ui-prototype/snapshots/fixture'
            snapshot.mkdir(parents=True);source=root/'source';source.mkdir();generated={}
            for name,data in (('a.png',b'aaa'),('b.png',b'bbb'),('c.png',b'ccc')):
                (snapshot/name).write_bytes(data)
                generated[name]=hashlib.sha256(data).hexdigest()
            (snapshot/'assets').mkdir();(snapshot/'assets/portrait.png').write_bytes(b'img')
            textures=json.dumps({'portrait':dict(url='assets/portrait.png',sha256=hashlib.sha256(b'img').hexdigest())}).encode()
            (snapshot/'textures.json').write_bytes(textures)
            generated['textures.json']=hashlib.sha256(textures).hexdigest()
            manifest=json.dumps(dict(generated_files=generated)).encode()
            (snapshot/'manifest.json').write_bytes(manifest)
            selector=root/'selector.json'
            selector.write_text(json.dumps(dict(snapshot='maps/ui-prototype/snapshots/fixture',
                manifest_sha256=hashlib.sha256(manifest).hexdigest())),encoding='utf-8')
            with patch.object(prototype_assets,'SOURCE',source),patch.object(prototype_assets,'SELECTOR',selector):
                view=prototype_assets.PrototypeAssets(root,'fixture-token')
            self.assertEqual(view.get('/prototype/manifest.json')[0],manifest)
            self.assertEqual(view.get('/prototype/assets/portrait.png')[0],b'img')
            view.cache.clear();view.cache_bytes=0;view.CACHE_BUDGET=6
            view.get('/prototype/a.png');view.get('/prototype/b.png')
            view.get('/prototype/a.png');view.get('/prototype/c.png')
            self.assertEqual(list(view.cache),['a.png','c.png'])
            self.assertEqual(view.cache_bytes,6)
            (view.snapshot/'b.png').write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError,'ресурс'):
                view.get('/prototype/b.png')
            self.assertIsNone(view.get('/prototype/../a.png'))
            self.assertIsNone(view.get('/prototype/unknown.png'))

    def test_first_verification_records_existing_pc_keys_without_replacing_a_complete_binding(self):
        spec = importlib.util.spec_from_file_location('verify_binding_fixture', HERE / 'vampir-headless/verify-account.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        runner = MagicMock()
        registry = runner.DeviceRegistry.return_value
        registry.get.side_effect = KeyError('not bound')
        identity = SimpleNamespace(device_key='observed-sdk', nm_device_key='observed-nm', nid_device_key='observed-nid')
        runner.observe_windows_device_identity.return_value = identity
        tool.ensure_pc_binding(runner, 'fixture@gmail.com')
        registry.register.assert_called_once_with('fixture@gmail.com', kind='real')
        self.assertEqual(registry.record_real_identity.call_args.kwargs['device_key'], 'observed-sdk')
        self.assertEqual(registry.record_real_nid_identity.call_args.kwargs['nid_device_key'], 'observed-nid')
        runner.reset_mock()
        registry.get.side_effect = None
        registry.get.return_value = SimpleNamespace(kind='real', identity_recorded=True, nid_identity_recorded=True)
        tool.ensure_pc_binding(runner, 'fixture@gmail.com')
        runner.observe_windows_device_identity.assert_not_called()
        registry.register.assert_not_called()

    def test_google_nid_result_keeps_provider_29_and_sdk_33_distinct(self):
        from vampir_core.nid_google import parse_nid_google_callback
        from vampir_core.nid_result import parse_nid_email_callback
        from vampir_core.nid_sdk_credential import build_nid_sdk_credential
        url = ('nmthered://nmidprovider/result?resultCode=0&accessToken=netmarble-fixture&refreshToken='
               '&channelKey=googleIdKey&netmarbleId=fixture-id&joinedCountryCode=UA')
        credential = parse_nid_google_callback(url, expected_game_code='thered')
        self.assertEqual(credential.channel_type, 29)
        self.assertEqual(build_nid_sdk_credential(credential).as_object(),
                         dict(channelAccessToken='netmarble-fixture', channelCode=33))
        self.assertNotIn('netmarble-fixture', repr(credential))
        with self.assertRaises(ValueError):
            parse_nid_email_callback(url, expected_game_code='thered')
        for invalid in (url.replace('googleIdKey', 'mailUserKey'), url.replace('resultCode=0', 'resultCode=1'),
                        url + '&accessToken=duplicate', url.replace('nmthered:', 'nmother:')):
            with self.assertRaises(ValueError):
                parse_nid_google_callback(invalid, expected_game_code='thered')

    @unittest.skipUnless(sys.platform == 'win32', 'Windows managed bridge')
    def test_google_external_bridge_checks_route_and_account_without_opening_a_browser(self):
        source = str((HERE / 'vampir-headless/windows/nid-google-bridge.cs').resolve()).replace("'", "''")
        script = """$ErrorActionPreference='Stop'
Add-Type -Path '__SOURCE__' -ReferencedAssemblies System.Web,System.Web.Extensions
$nested='https://members.netmarble.com/auth/idp/start/external-browser/google?webViewType=sdk&clientId=fixture&encodedIdpUrl=https%3A%2F%2Faccounts.google.com%2F'
$target='nmthered://nmwebview/showExternalBrowser?url='+[Uri]::EscapeDataString($nested)+'&callback=onIDPResponse'
if (-not [NidGoogleBridge]::ExternalUrl($target,'thered')) { throw 'expected external route' }
if ([NidGoogleBridge]::ExternalUrl($target.Replace('callback=onIDPResponse','callback=other'),'thered')) { throw 'wrong callback accepted' }
if ([NidGoogleBridge]::ExternalUrl($target.Replace('nmthered:','nmother:'),'thered')) { throw 'wrong game accepted' }
$claims='{"email":"fixture@gmail.com","email_verified":true,"iss":"https://accounts.google.com","aud":"fixture.apps.googleusercontent.com"}'
$payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($claims)).TrimEnd('=').Replace('+','-').Replace('/','_')
$query='?idToken=fixture.'+$payload+'.fixture'
if (-not [NidGoogleBridge]::MatchesGoogleAccount($query,'fixture@gmail.com')) { throw 'account binding failed' }
if ([NidGoogleBridge]::MatchesGoogleAccount($query,'other@gmail.com')) { throw 'wrong account accepted' }
if ([NidGoogleBridge]::MatchesGoogleAccount('?idToken=malformed','fixture@gmail.com')) { throw 'bad token shape accepted' }
$bridge=[NidGoogleBridge]::new()
$client=[Net.WebClient]::new()
$client.Proxy=$null
try {
  $script:opened=''
  $bridge.Start($nested,'fixture@gmail.com',[Action[string]]{param($url) $script:opened=$url})
  $redirect=[Web.HttpUtility]::ParseQueryString(([Uri]$script:opened).Query)['redirectUrl']
  try { $null=$client.DownloadString($redirect.Replace(([Uri]$redirect).AbsolutePath,'/wrong/')+$query); throw 'bad nonce accepted' }
  catch [Net.WebException] { if ([int]$_.Exception.Response.StatusCode -ne 403) { throw } }
  $null=$client.DownloadString($redirect+$query)
  if ($bridge.Response.Result -ne $query.Substring(1)) { throw 'callback query shape differs' }
  if (-not $bridge.AccountMatched) { throw 'callback email unconfirmed' }
} finally { $bridge.Dispose();$client.Dispose() }
[Console]::Write('passed')
""".replace('__SOURCE__', source)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'bridge.ps1'
            path.write_text(script, encoding='utf-8-sig')
            result = __import__('subprocess').run(['powershell.exe', '-NoProfile', '-File', str(path)],
                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', 'replace'))
        self.assertEqual(result.stdout.decode('utf-8-sig'), 'passed')

    def test_google_verification_uses_manual_input_and_never_reads_mail_credentials(self):
        from contextlib import nullcontext
        spec = importlib.util.spec_from_file_location('google_verify_fixture', HERE / 'vampir-headless/verify-account.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('fixture@gmail.com', assignment={'login_provider': 'google', 'device_name': 'DESKTOP-ABC1234'})
            runner, nid = MagicMock(), MagicMock()
            from vampir_core.gmc2_context import SdkInputs
            prepared = MagicMock(spec=SdkInputs)
            prepared.source_sha256 = 'fixture-source'
            prepared.selected_profile = 'fixture-profile'
            prepared.binding = SimpleNamespace(device_key='fixture-sdk', nm_device_key='fixture-nm')
            runner.load_inputs.return_value = prepared
            runner.run.return_value = SimpleNamespace(verification_steps=('device-registration', 'workplace'))
            modules = {'run-nid-sdk-sign-in': runner, 'nid-browser': nid}
            with patch.object(tool, 'load', side_effect=lambda name: modules[name]), \
                    patch.object(tool, 'scope', return_value=nullcontext()), patch.object(tool, 'check_source'), \
                    patch.object(tool, 'check_google_web'), patch.object(tool, 'web_url', return_value='https://fixture.invalid') as url, \
                    patch.object(tool, 'browser', return_value='verified') as browser, \
                    patch.object(store, 'credential', side_effect=AssertionError('No password for Google')), \
                    patch.object(store, 'reveal_password', side_effect=AssertionError('No IMAP for Google')):
                result = tool.verify(store, identifier, selector='fixture-profile')
            self.assertEqual(result, ('verified', ['device-registration', 'workplace']))
            self.assertEqual(runner.run.call_args.kwargs['password'], '')
            self.assertTrue(runner.run.call_args.kwargs['_capture'].keywords['manual_google'])
            self.assertEqual(browser.call_count, 2)
            self.assertTrue(all(call.args[3] == 'DESKTOP-ABC1234' for call in url.call_args_list))
            self.assertTrue(all(call.kwargs['mailbox'] is None for call in browser.call_args_list))

    def test_existing_sdk_authorization_completes_forms_before_any_lobby_connection(self):
        from vampir_core.gmc2_context import SdkInputs, Gmc2Geo, LATEST_SOURCE_SHA256, MAX_CONTEXT_AGE
        from vampir_core.sdk_sign_in_response import SdkSignInData
        spec = importlib.util.spec_from_file_location('entry_verification_fixture', HERE / 'vampir-headless/verify-account.py')
        verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
        spec = importlib.util.spec_from_file_location('entry_lobby_fixture', HERE / 'vampir-headless/probe-lobby-sdk-login.py')
        lobby = importlib.util.module_from_spec(spec); spec.loader.exec_module(lobby)
        for steps, browser_status, expire, expected in (
                (('device-registration', 'workplace'), 'verified', False, ['device-registration', 'workplace']),
                (('device-registration', 'workplace'), 'server_rejected', False, ['device-registration']),
                (None, 'verified', False, []),
                (('device-registration',), 'verified', True, ['device-registration']),
                ((), 'verified', False, [])):
            with self.subTest(steps=steps, result=browser_status, expire=expire):
                events = []
                binding = SimpleNamespace(device_key='sdk-fixture', nm_device_key='nm-fixture')
                prepared = SdkInputs('fixture@vampir.top', binding, {'game_code': 'thered'}, {},
                    'recovered-release', None, LATEST_SOURCE_SHA256,
                    Gmc2Geo('1.1.1.1', 'UA', 'UA', 'fixture-body', LATEST_SOURCE_SHA256), time.monotonic())
                data = SdkSignInData('token-fixture', 'player-fixture', 'EU', 'UA', 1, steps)
                provider = SimpleNamespace(netmarble_id='nid-fixture', joined_country_code='UA')
                nid, mail = MagicMock(), MagicMock()
                def form(purpose, **kwargs):
                    events.append(purpose)
                    if expire:
                        object.__setattr__(prepared, 'fetched_at', time.monotonic() - MAX_CONTEXT_AGE - 1)
                    return browser_status
                def sdk_run(email, **kwargs):
                    events.append('sdk')
                    kwargs['_capture']('https://fixture.invalid')
                    self.assertIs(kwargs['_prepared_inputs'], prepared)
                    return data
                sdk = SimpleNamespace(load_inputs=MagicMock(return_value=prepared), run=MagicMock(side_effect=sdk_run))
                modules = [SimpleNamespace(load_profile=lambda **kwargs: SimpleNamespace(app_version='fixture',
                    source_snapshot_sha256='fixture-snapshot', source_exe_sha256=LATEST_SOURCE_SHA256)),
                    SimpleNamespace(selected_endpoint=lambda *args, **kwargs: ('lobby.invalid', 1)), sdk,
                    SimpleNamespace(capture_nid_credential=lambda *args, **kwargs: provider),
                    SimpleNamespace(prepare_version=lambda **kwargs: object(), observe_computer_name=lambda: 'fixture')]
                def continuation(**kwargs):
                    self.assertIs(kwargs['prepared'], prepared); self.assertIs(kwargs['data'], data)
                    status, _ = verifier.continue_verification(email='fixture@vampir.top', settings={},
                        prepared=prepared, data=data, mail_password='mail-fixture')
                    return status
                def connect(*args, **kwargs):
                    events.append('lobby-connect')
                    return MagicMock()
                exchange = MagicMock(return_value=SimpleNamespace(summary={}, response=SimpleNamespace(result_code=0)))
                with patch.object(lobby, 'module', side_effect=modules), patch.object(lobby, 'connect_direct', side_effect=connect) as socket, \
                        patch.object(lobby, 'observe_windows_version', return_value=None), patch.object(lobby, 'exchange_lobby_login', exchange), \
                        patch.object(verifier, 'load', side_effect=lambda name: {'nid-browser': nid, 'nid-mail-code': mail}[name]), \
                        patch.object(verifier, 'check_source'), patch.object(verifier, 'web_url', return_value='https://fixture.invalid'), \
                        patch.object(verifier, 'browser', side_effect=form):
                    kwargs = dict(selected_profile='recovered-release', manifest_path=Path('fixture'), socks_port=None,
                        context='sdk-without-nid-info', _verification=continuation)
                    success = steps is not None and browser_status == 'verified' and not expire
                    if success:
                        lobby.run('fixture@vampir.top', **kwargs)
                        self.assertEqual(events, ['sdk'] + expected + ['lobby-connect'])
                        socket.assert_called_once(); exchange.assert_called_once()
                    else:
                        with self.assertRaises(ValueError): lobby.run('fixture@vampir.top', **kwargs)
                        self.assertEqual(events, ['sdk'] + expected)
                        socket.assert_not_called(); exchange.assert_not_called()
                sdk.run.assert_called_once()
                self.assertEqual(mail.RegistrationMailbox.call_count, len(expected))
                self.assertEqual(mail.RegistrationMailbox.return_value.close.call_count, len(expected))

    def test_worker_passes_existing_sdk_context_and_records_only_confirmed_device(self):
        spec = importlib.util.spec_from_file_location('worker_verification_fixture', HERE / 'vampir-headless/account-worker.py')
        worker = importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)
        spec = importlib.util.spec_from_file_location('worker_verifier_type_fixture', HERE / 'vampir-headless/verify-account.py')
        verifier_types = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier_types)
        for status, fingerprint_matches in (('verified', True), ('server_rejected', True), ('unknown_player_status', True), ('verified', False)):
            with self.subTest(status=status, fingerprint_matches=fingerprint_matches):
                store, registry, cdn, lobby = MagicMock(), MagicMock(), MagicMock(), MagicMock()
                store.credential.return_value = ('fixture@vampir.top', 'game-fixture', dict(enabled=True, region='EU', server_id=387))
                store.record_device_verification.return_value = fingerprint_matches
                cdn.profile.return_value = dict(url='https://fixture.invalid')
                cdn.fetch.return_value = (b'fixture', {})
                cdn.save.return_value = (Path('fixture'), None)
                prepared, data = object(), SimpleNamespace(verification_steps=('device-registration',))
                verifier = SimpleNamespace(VerificationStopped=verifier_types.VerificationStopped,
                    continue_verification=MagicMock(return_value=(status, ['device-registration'] if status == 'verified' else [])))
                def run_lobby(*args, **kwargs):
                    kwargs['_verification'](prepared=prepared, data=data)
                    return SimpleNamespace(server_list_response=SimpleNamespace(result_code=0))
                lobby.run.side_effect = run_lobby
                def load(name, path):
                    return {'fetch-public-cdn-config.py': cdn, 'probe-lobby-sdk-login.py': lobby, 'verify-account.py': verifier}[path.name]
                with patch.object(worker, 'AccountStore', return_value=store), patch.object(worker, 'DeviceRegistry', return_value=registry), \
                        patch.object(worker, 'load', side_effect=load), patch.object(worker, 'build_account_catalog', return_value={}), \
                        patch.object(worker, 'emit'):
                    args = SimpleNamespace(store=Path('fixture'), account='fixture-id', operation='servers')
                    if status == 'verified' and fingerprint_matches:
                        worker.run(args)
                    else:
                        with self.assertRaises(verifier_types.VerificationStopped) as failure:
                            worker.run(args)
                        self.assertNotIn('fixture', str(worker.failure(failure.exception)))
                self.assertEqual(verifier.continue_verification.call_count, 1)
                self.assertIs(verifier.continue_verification.call_args.kwargs['prepared'], prepared)
                self.assertIs(verifier.continue_verification.call_args.kwargs['data'], data)
                self.assertEqual(store.record_device_verification.call_count, int(status == 'verified'))
                if status != 'verified' or not fingerprint_matches: store.save_catalog.assert_not_called()

    def test_terminal_verification_accepts_server_success_after_local_gmc2_expiry(self):
        from vampir_core.gmc2_context import SdkInputs, Gmc2Geo, LATEST_SOURCE_SHA256, MAX_CONTEXT_AGE
        from vampir_core.sdk_sign_in_response import SdkSignInData
        spec = importlib.util.spec_from_file_location('terminal_verification_fixture', HERE / 'vampir-headless/verify-account.py')
        verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
        binding = SimpleNamespace(device_key='sdk-fixture', nm_device_key='nm-fixture')
        prepared = SdkInputs('fixture@vampir.top', binding, {'game_code': 'thered'}, {},
            'recovered-release', None, LATEST_SOURCE_SHA256,
            Gmc2Geo('1.1.1.1', 'UA', 'UA', 'fixture-body', LATEST_SOURCE_SHA256), time.monotonic())
        data = SdkSignInData('token-fixture', 'player-fixture', 'EU', 'UA', 1, ('device-registration', 'workplace'))
        nid, mail = MagicMock(), MagicMock()
        def form(purpose, **kwargs):
            # The server's mail-code/form deadline remains independently enforced by browser().
            object.__setattr__(prepared, 'fetched_at', time.monotonic() - MAX_CONTEXT_AGE - 1)
            return 'verified'
        with patch.object(verifier, 'load', side_effect=lambda name: {'nid-browser': nid, 'nid-mail-code': mail}[name]), \
                patch.object(verifier, 'check_source'), patch.object(verifier, 'web_url', return_value='https://fixture.invalid'), \
                patch.object(verifier, 'browser', side_effect=form) as browser:
            result = verifier.continue_verification(email='fixture@vampir.top', settings={}, prepared=prepared,
                data=data, mail_password='mail-fixture', require_fresh_context=False)
        self.assertEqual(result, ('verified', ['device-registration', 'workplace']))
        self.assertEqual(browser.call_count, 2)
        with self.assertRaises(ValueError):
            prepared.check_usage(email='fixture@vampir.top', selected_profile='recovered-release', route=None)

    def test_selected_entry_forwards_one_verification_continuation_and_redacts_its_failure(self):
        spec = importlib.util.spec_from_file_location('selected_verification_fixture', HERE / 'vampir-headless/probe-selected-game-login.py')
        selected = importlib.util.module_from_spec(spec); spec.loader.exec_module(selected)
        callback = MagicMock()
        lobby = SimpleNamespace(run=MagicMock(return_value=object()))
        modules = [SimpleNamespace(load_profile=lambda **kwargs: SimpleNamespace(app_version='fixture')), lobby]
        kwargs = dict(selected_profile='recovered-base', manifest_path=Path('fixture'), socks_port=None,
            server_policy_byte=0, extra_number=1, context='windows-sdk-initial-reset', region='EU', server_id=387,
            server_list_only=True, _verification=callback)
        with patch.object(selected, 'module', side_effect=modules), patch.object(selected, '_after_lobby', return_value={'fixture': 'finished'}):
            result = selected.run('fixture@vampir.top', **kwargs)
        self.assertEqual(result, {'fixture': 'finished'})
        lobby.run.assert_called_once()
        self.assertIs(lobby.run.call_args.kwargs['_verification'], callback)
        error = RuntimeError('private-token-fixture')
        error.verification_status = 'server_rejected'
        with patch.object(selected, '_run', side_effect=error):
            result = selected.run('fixture@vampir.top', **kwargs)
        self.assertEqual(result['verification_status'], 'server_rejected')
        self.assertNotIn('private', str(result))

    def test_current_pc_observation_copies_hardware_without_private_identity(self):
        from vampir_core.version_cpu import VersionCpuInput
        from vampir_core.windows_version import WindowsVersion
        spec = importlib.util.spec_from_file_location('current_pc_fixture', HERE / 'vampir-headless/current-pc.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        hardware = dict(manufacturer='Fixture Vendor', model='Fixture PC', memory_bytes=32 * 2**30,
            gpu=['Fixture GPU', 'Fixture GPU'], os_caption='Windows fixture', os_version='10.0.12345',
            timezone='Fixture Time', locale='uk-UA')
        result = tool.observation(_system=lambda: (VersionCpuInput('GenuineIntel', 'Fixture CPU'),
            WindowsVersion(10, 0, 12345, 1, 256)), _hardware=lambda: hardware)
        self.assertNotIn('identity', result['device_settings'])
        self.assertEqual(result['device_settings']['cpu']['brand'], 'Fixture CPU')
        self.assertEqual(result['display_metadata']['I_NMRAM'], '32.00 GiB')
        self.assertEqual(result['display_metadata']['I_NMVGA'], 'Fixture GPU')
        self.assertEqual(result['display_metadata']['I_DeviceModel'], 'Fixture Vendor Fixture PC')
        self.assertIn('10.0.12345', result['os_display'])
        self.assertFalse(result['unknown'])
        failed = MagicMock(side_effect=RuntimeError('fixture reader unavailable'))
        unavailable = tool.observation(_system=failed, _hardware=failed)
        self.assertEqual(unavailable['device_settings'], {})
        self.assertEqual(len(unavailable['unknown']), 2)

    def test_google_accounts_have_no_netmarble_password_and_keep_their_provider(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'console.sqlite3'
            store = AccountStore(path, FixtureVault())
            identifier = store.save('google@unit.invalid', assignment={'login_provider': 'google', 'server_id': 381})
            store.save('google@unit.invalid', assignment={'login_provider': 'google', 'server_id': 382})
            account, = AccountStore(path, FixtureVault()).accounts()
            self.assertEqual(account['id'], identifier)
            self.assertEqual(account['login_provider'], 'google')
            self.assertFalse(account['password_saved'])
            self.assertFalse(account['mail_password_saved'])
            self.assertEqual(account['server_id'], 382)
            with self.assertRaisesRegex(ValueError, 'Google'):
                store.credential(identifier)
            with self.assertRaisesRegex(ValueError, 'not saved'):
                store.reveal_password(identifier, 'netmarble')
            with self.assertRaises(ValueError):
                store.save(account['email'], password='not-a-google-password', assignment={'login_provider': 'google'})
            with self.assertRaises(ValueError):
                store.save(account['email'], password='fixture', assignment={})
            self.assertFalse(store.accounts()[0]['password_saved'])
            email_id = store.save('email@unit.invalid', password='fixture', assignment={})
            with self.assertRaises(ValueError):
                store.save('email@unit.invalid', assignment={'login_provider': 'google'})
            email = next(a for a in store.accounts() if a['id'] == email_id)
            self.assertEqual(email['login_provider'], 'email')
            self.assertTrue(email['password_saved'])

    def test_google_manual_login_cannot_start_the_email_worker(self):
        spec = importlib.util.spec_from_file_location('google_account_jobs', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('google@unit.invalid', assignment={'login_provider': 'google'})
            jobs = tool.Jobs(store)
            with patch.object(tool.subprocess, 'Popen') as popen:
                for operation in ('servers', 'characters', 'start', 'create', 'prepare-sdk'):
                    for manual in (True, False):
                        with self.assertRaisesRegex(ValueError, 'Google'):
                            jobs.start(identifier, operation, manual_sign_in=manual)
                with self.assertRaisesRegex(ValueError, 'Google'):
                    jobs.start(identifier, 'register')
                popen.assert_not_called()
            verifier = MagicMock()
            verifier.selected_profile.return_value = 'sdk-launcher:fixture'
            with patch.object(tool.importlib.util, 'spec_from_file_location'), \
                    patch.object(tool.importlib.util, 'module_from_spec', return_value=verifier), \
                    patch.object(tool.subprocess, 'Popen') as popen, patch.object(tool.threading, 'Thread'):
                jobs.verify_batch([identifier])
                self.assertIn('--manual-sign-in', popen.call_args.args[0])
                self.assertEqual(jobs.verification_snapshot()['active'], identifier)

    def test_manual_verification_resumes_saved_queue_without_repeating_completed_accounts(self):
        spec = importlib.util.spec_from_file_location('manual_verification_queue', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            done, failed, waiting = [store.save(f'{index}@vampir.top', password='fixture', mail_password='mail', assignment={})
                                     for index in range(3)]
            store.save_verification_checkpoint(dict(state='stopped', active=None, completed=[done], pending=[waiting],
                                                    failed=failed, manual_retry=True, message='NID refused'))
            jobs = tool.Jobs(store)
            success = b'{"event":"result","status":"verified","message":"fixture"}\n'
            manual = MagicMock(stdout=io.BytesIO(success), stdin=None, returncode=0)
            following = MagicMock(stdout=io.BytesIO(success), stdin=None, returncode=0)
            with patch.object(tool.subprocess, 'Popen', side_effect=[manual, following]) as popen, \
                    patch.object(tool.threading, 'Thread'):
                with self.assertRaises(ValueError):
                    jobs.verify_batch([done])
                jobs.resume_verification_manually()
                command = popen.call_args.args[0]
                self.assertIn(failed, command)
                self.assertIn('--manual-sign-in', command)
                self.assertEqual(store.load_verification_checkpoint()['completed'], [done])
                jobs._watch(jobs.jobs[failed])
                command = popen.call_args.args[0]
                self.assertIn(waiting, command)
                self.assertNotIn('--manual-sign-in', command)
                jobs._watch(jobs.jobs[waiting])
                self.assertEqual(tool.Jobs(store).verification_snapshot()['completed'], [done, failed, waiting])
                self.assertEqual(store.load_verification_checkpoint()['state'], 'completed')

    def test_active_game_roster_updates_existing_account_without_reusing_old_character_slot(self):
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            address = 'roster@vampir.top'
            identifier = store.save(address, password='fixture', mail_password='mail', assignment=dict(
                server_id=381, character_index=0, character_key='123', label='Personal label'))
            store.save_characters(identifier, region='EU', server_id=381, observed_utc='2026-11-05T20:00:00Z',
                                  characters=[dict(index=0, key='123', name='Old server character')])
            store.registration_status(identifier, 'registered')
            entry = dict(email=address, region='EU', server_id=385, character_name='Reported', device='UgPhone')
            with self.assertRaises(ValueError):
                store.update_active_game_roster([entry, dict(entry, email='missing@vampir.top')])
            self.assertEqual(store.accounts()[0]['server_id'], 381)
            self.assertFalse(store.accounts()[0]['active_game_account'])

            self.assertEqual(store.update_active_game_roster([entry]), 1)
            self.assertEqual(store.update_active_game_roster([entry]), 0)
            updated, = store.accounts()
            self.assertEqual(updated['server_id'], 385)
            self.assertIsNone(updated['character_index'])
            self.assertIsNone(updated['character_key'])
            self.assertEqual(updated['id'], identifier)
            self.assertEqual(updated['label'], 'Personal label')
            self.assertEqual(updated['registration_status'], 'registered')
            self.assertTrue(updated['mail_password_saved'])
            self.assertTrue(updated['active_game_account'])
            self.assertEqual(updated['reported_character_name'], 'Reported')
            self.assertEqual(updated['reported_device'], 'UgPhone')
            store.update_active_game_roster([{k: v for k, v in entry.items() if k != 'device'}])
            self.assertEqual(store.accounts()[0]['reported_device'], 'UgPhone')
            with self.assertRaises(ValueError):
                store.update_active_game_roster([dict(entry, device='bad\nvalue')])
            self.assertEqual(store.accounts()[0]['reported_device'], 'UgPhone')
            self.assertEqual(store.character_lists()[identifier + '|EU|381']['characters'][0]['key'], '123')
            store.save(address, assignment=dict(server_id=386))
            self.assertTrue(store.accounts()[0]['active_game_account'])
            self.assertIsNone(store.accounts()[0]['reported_character_name'])

    def test_verification_queue_waits_for_cleanup_and_cancel_stops_next_account(self):
        spec = importlib.util.spec_from_file_location('verification_queue', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            ids = [store.save(f'fixture-{index}@vampir.top', password='fixture', mail_password='mail', assignment={})
                   for index in range(3)]
            jobs = tool.Jobs(store)
            success = b'{"event":"result","status":"verified","message":"fixture"}\n'
            first = MagicMock(stdout=io.BytesIO(success), stdin=None, returncode=0)
            second = MagicMock(stdout=io.BytesIO(success), stdin=None, returncode=0)
            def launch(*args, **kwargs):
                if first.stdout.closed:
                    self.assertTrue(first.wait.called)
                    return second
                return first
            with patch.object(tool.subprocess, 'Popen', side_effect=launch) as popen, \
                    patch.object(tool.threading, 'Thread'), patch.object(jobs, '_terminate'):
                with self.assertRaises(ValueError):
                    jobs.verify_batch([ids[0], ids[0]])
                self.assertEqual(popen.call_count, 0)
                jobs.verify_batch(ids)
                self.assertEqual(jobs.verification_snapshot()['active'], ids[0])
                with self.assertRaises(ValueError):
                    jobs.start(ids[1], 'servers')
                jobs._watch(jobs.jobs[ids[0]])
                self.assertEqual(jobs.verification_snapshot()['active'], ids[1])
                self.assertEqual(jobs.verification_snapshot()['completed'], ids[:1])
                jobs.stop_verification()
                jobs._watch(jobs.jobs[ids[1]])
                self.assertEqual(jobs.verification_snapshot()['state'], 'cancelled')
                self.assertEqual(jobs.verification_snapshot()['pending'], ids[2:])
                self.assertEqual(popen.call_count, 2)

    def test_creation_nickname_reuses_persisted_proposal_and_changes_only_after_confirmed_collision(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'console.sqlite3'
            store = AccountStore(path, FixtureVault())
            identifier = store.save('one@unit.invalid', password='fixture', assignment={'region': 'EU', 'server_id': 384})
            self.assertEqual(store.accounts()[0]['create_class'], 'Gunner')
            with self.assertRaises(ValueError): store.creation_nickname(identifier, region='EU', server_id=384)
            store.save_characters(identifier, region='EU', server_id=384, characters=[], observed_utc='2026-10-22T20:00:00+00:00')
            first = store.creation_nickname(identifier, region='EU', server_id=384)
            self.assertRegex(first, r'^[A-Z][a-z]{9}$')
            store = AccountStore(path, FixtureVault())
            self.assertEqual(first, store.creation_nickname(identifier, region='EU', server_id=384))
            for outcome in ('timeout', 'unknown', 'connection_closed'):
                with self.assertRaises(ValueError):
                    store.creation_nickname(identifier, region='EU', server_id=384, result=outcome, rejected_name=first)
                self.assertEqual(store.accounts()[0]['create_nickname'], first)
            with self.assertRaises(ValueError):
                store.creation_nickname(identifier, region='EU', server_id=384, result='name_taken', rejected_name='other')
            second = store.creation_nickname(identifier, region='EU', server_id=384, result='name_taken', rejected_name=first)
            self.assertNotEqual(first, second)
            self.assertEqual(store.accounts()[0]['create_class'], 'Gunner')
            for _ in range(3):
                second = store.creation_nickname(identifier, region='EU', server_id=384, result='name_taken', rejected_name=second)
            with self.assertRaises(ValueError):
                store.creation_nickname(identifier, region='EU', server_id=384, result='name_taken', rejected_name=second)
            self.assertEqual(store.accounts()[0]['create_nickname'], second)

    def test_creation_name_requires_empty_list_for_same_account_and_target(self):
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('one@unit.invalid', password='fixture', assignment={'region': 'EU', 'server_id': 384,
                'create_class': 'Fighter', 'create_nickname': 'ManualName', 'create_random_nickname': False})
            second = store.save('two@unit.invalid', password='fixture', assignment={'region': 'EU', 'server_id': 384})
            store.save_characters(identifier, region='EU', server_id=384, characters=[], observed_utc='2026-10-22T20:00:00+00:00')
            for account, region, server in ((second, 'EU', 384), (identifier, 'JP', 384), (identifier, 'EU', 385)):
                with self.assertRaises(ValueError): store.creation_nickname(account, region=region, server_id=server)
            self.assertEqual('ManualName', store.creation_nickname(identifier, region='EU', server_id=384))
            with self.assertRaises(ValueError):
                store.creation_nickname(identifier, region='EU', server_id=384, result='name_taken', rejected_name='ManualName')
            self.assertEqual(store.accounts()[0]['create_class'], 'Fighter')
            store.save_characters(identifier, region='EU', server_id=384,
                characters=[dict(index=0, key='123', name='Existing')], observed_utc='2026-10-22T20:01:00+00:00')
            with self.assertRaises(ValueError): store.creation_nickname(identifier, region='EU', server_id=384)

    def test_sdk_creation_is_not_available_in_account_console(self):
        spec = importlib.util.spec_from_file_location('sdk_removed_test', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('fixture@unit.invalid', password='fixture', assignment={})
            store.registration_status(identifier, 'nid_verified')
            jobs = tool.Jobs(store)
            jobs.jobs[identifier] = dict(running=False, sdk_error=dict(code=1203))
            with patch.object(tool.subprocess, 'Popen') as popen:
                with self.assertRaises(ValueError): jobs.start(identifier, 'sdk_register')
                popen.assert_not_called()

    def test_server_loading_uses_selected_signin_flow_without_signup(self):
        spec = importlib.util.spec_from_file_location('account_signin_test', HERE / 'vampir-headless/account-worker.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        for flow, manual in (('launcher', False), ('nid', False), ('launcher', True), ('nid', True)):
            store, registry, cdn, lobby = MagicMock(), MagicMock(), MagicMock(), MagicMock()
            store.credential.return_value = ('fixture@unit.invalid', 'fixture-password',
                dict(enabled=True, region='EU', server_id=384, auth_flow=flow))
            cdn.profile.return_value = dict(url='https://fixture.invalid')
            cdn.fetch.return_value = (b'fixture-body', {})
            cdn.save.return_value = (Path('fixture-manifest.json'), None)
            lobby.run.return_value.server_list_response.result_code = 0
            def load(name, path):
                if path.name == 'fetch-public-cdn-config.py': return cdn
                if path.name == 'probe-lobby-sdk-login.py': return lobby
                self.fail('Unexpected module in sign-in: ' + path.name)
            with patch.object(tool, 'AccountStore', return_value=store), \
                 patch.object(tool, 'DeviceRegistry', return_value=registry), patch.object(tool, 'load', side_effect=load), \
                 patch.object(tool, 'build_account_catalog', return_value={}), patch.object(tool, 'emit'):
                tool.run(SimpleNamespace(store=Path('fixture.sqlite3'), account='fixture-id', operation='servers', manual_sign_in=manual))
            self.assertEqual(lobby.run.call_args.kwargs['auth_flow'], flow)
            self.assertEqual(lobby.run.call_args.kwargs['password'], '' if manual else 'fixture-password')
            self.assertNotIn('create_sdk_player', lobby.run.call_args.kwargs)
            store.save_catalog.assert_called_once_with('EU', {})

    def test_manual_signin_flag_is_explicit_and_rejects_registration(self):
        spec = importlib.util.spec_from_file_location('manual_signin_job_test', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('fixture@unit.invalid', password='fixture', assignment={})
            jobs = tool.Jobs(store)
            with patch.object(tool.subprocess, 'Popen') as popen, patch.object(tool.threading, 'Thread'):
                with self.assertRaises(ValueError): jobs.start(identifier, 'register', manual_sign_in=True)
                with self.assertRaises(ValueError): jobs.start(identifier, 'characters', manual_sign_in=1)
                popen.assert_not_called()
                jobs.start(identifier, 'characters', manual_sign_in=True)
                self.assertIn('--manual-sign-in', popen.call_args.args[0])
                self.assertTrue(jobs.snapshot()[identifier]['manual_sign_in'])
                self.assertNotIn('fixture@unit.invalid', popen.call_args.args[0])

    def test_character_operation_saves_catalog_from_same_login_and_never_selects_character(self):
        spec = importlib.util.spec_from_file_location('account_chain_test', HERE / 'vampir-headless/account-worker.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        for code in (0, 59):
            store, registry, cdn, login = MagicMock(), MagicMock(), MagicMock(), MagicMock()
            store.credential.return_value = ('fixture@unit.invalid', 'fixture-password',
                dict(enabled=True, region='EU', server_id=384, auth_flow='launcher', character_index=0, character_key='123'))
            cdn.profile.return_value = dict(url='https://fixture.invalid')
            cdn.fetch.return_value = (b'fixture-body', {})
            cdn.save.return_value = (Path('fixture-manifest.json'), None)
            def login_run(*args, **kwargs):
                kwargs['_server_list_observer'](SimpleNamespace(result_code=code))
                self.assertIsNone(kwargs['character_index'])
                self.assertTrue(kwargs['read_character_list'])
                self.assertFalse(kwargs['read_world_start'])
                self.assertFalse(kwargs['read_world_finish'])
                return dict(status='game_login_probe', game=dict(login_result_code=0,
                    character_list_received=True, character_list_result_code=0,
                    characters=[dict(index=0, key='123', name='Existing')]))
            login.run.side_effect = login_run
            def load(name, path):
                if path.name == 'fetch-public-cdn-config.py': return cdn
                if path.name == 'probe-selected-game-login.py': return login
                self.fail('Second authentication or unexpected module: ' + path.name)
            with patch.object(tool, 'AccountStore', return_value=store), \
                 patch.object(tool, 'DeviceRegistry', return_value=registry), patch.object(tool, 'load', side_effect=load), \
                 patch.object(tool, 'build_account_catalog', return_value={'fixture': True}), patch.object(tool, 'emit'), \
                 patch.object(tool.Path, 'read_bytes', return_value=b'fixture'), patch.object(tool, 'parse_patch_client_revision', return_value=123):
                args = SimpleNamespace(store=Path('fixture.sqlite3'), account='fixture-id', operation='characters')
                if code == 0:
                    tool.run(args)
                    store.save_catalog.assert_called_once_with('EU', {'fixture': True})
                    store.save_characters.assert_called_once()
                else:
                    with self.assertRaises(ValueError): tool.run(args)
                    store.save_catalog.assert_not_called()
                    store.save_characters.assert_not_called()
            login.run.assert_called_once()
            store.creation_nickname.assert_not_called()

    def test_sdk_failure_keeps_only_numeric_status_and_code(self):
        spec = importlib.util.spec_from_file_location('worker_error_test', HERE / 'vampir-headless/account-worker.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        value = tool.failure(tool.SdkSignInHttpError('secret-server-text', 403, 123))
        self.assertEqual(value['sdk_error'], {'http_status': 403, 'code': 123})
        self.assertNotIn('secret', json.dumps(value))
        value = tool.failure(tool.SdkSignInHttpError('secret', 'private-status', 'private-code'))
        self.assertEqual(value['sdk_error'], {'http_status': None, 'code': None})
        self.assertNotIn('private', json.dumps(value))
        rejected = RuntimeError('private-browser-details')
        rejected.browser_status, rejected.nid_http_status, rejected.nid_error_code = 'login_failed', 400, 123
        rejected.sign_in_step = 'submitted'
        rejected.nid_response_state = 'no_numeric_code'
        value = tool.failure(rejected)
        self.assertIn('Login Failed', value['message'])
        self.assertIn('HTTP 400', value['message'])
        self.assertIn('Код NID: 123', value['message'])
        self.assertIn('форма отправлена', value['message'])
        self.assertIn('числовой код не найден', value['message'])
        self.assertNotIn('private', json.dumps(value))
        timeout = RuntimeError('private-browser-details')
        timeout.browser_status = 'timeout'
        value = tool.failure(timeout)
        self.assertIn('Истекло время входа Netmarble', value['message'])
        self.assertNotIn('private', json.dumps(value))
        rejected.nid_error_hint, rejected.nid_response_shape = 'rate_limited', 'message_only'
        value = tool.failure(rejected)
        self.assertIn('признак ограничения частоты', value['message'])
        self.assertIn('сообщение без числового кода', value['message'])
        rejected.nid_error_hint, rejected.nid_response_shape = 'private-fixture', 'private-fixture'
        self.assertNotIn('private', json.dumps(tool.failure(rejected)))

    def test_manual_registration_code_is_scoped_single_use_and_not_in_snapshot(self):
        import io
        spec = importlib.util.spec_from_file_location('console_code_test', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        process = MagicMock(); process.stdin = io.BytesIO(); process.poll.return_value = None
        jobs = tool.Jobs(SimpleNamespace(load_verification_checkpoint=lambda: None))
        jobs.jobs['fixture'] = dict(process=process, running=True, manual_mail_code=True,
            code_sent=False, stage='registration_code')
        for identifier, code in (('other', '12345'), ('fixture', '1234'), ('fixture', '１２３４５')):
            with self.assertRaises(ValueError): jobs.submit_code(identifier, code)
        jobs.submit_code('fixture', '12345')
        self.assertEqual(process.stdin.getvalue(), b'12345\n')
        self.assertNotIn('12345', json.dumps(jobs.snapshot()))
        with self.assertRaises(ValueError): jobs.submit_code('fixture', '54321')
        jobs.jobs['fixture'].update(code_sent=False, stage='registration_form')
        with self.assertRaises(ValueError): jobs.submit_code('fixture', '12345')

    def test_manual_registration_provider_does_not_open_imap(self):
        spec = importlib.util.spec_from_file_location('manual_registration_test', HERE / 'vampir-headless/register-nid-account.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        runner, browser, mail = MagicMock(), MagicMock(), MagicMock()
        runner.load_inputs.return_value = (object(), {'game_code': 'thered'}, {})
        modules = {'run-nid-sdk-sign-in.py': runner, 'nid-browser.py': browser, 'nid-mail-code.py': mail}
        provider = lambda: '12345'
        def capture(*args, **kwargs):
            self.assertIs(kwargs['code_provider'], provider)
            kwargs['progress']({'complete': True})
            return 'fixture-provider'
        browser.capture_nid_credential.side_effect = capture
        with patch.object(tool, 'module', side_effect=lambda name, filename: modules[filename]), \
             patch.object(tool, 'prepare_observed_profile'):
            self.assertEqual(tool.run('fixture@vampir.top', password='fixture', mail_password=None,
                selected_profile='recovered-release', accept_required_terms=True,
                _code_provider=provider, _progress=lambda state: None), 'fixture-provider')
        mail.RegistrationMailbox.assert_not_called()

    def test_character_lists_survive_restart_and_are_isolated_by_account_and_server(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'console.sqlite3'
            store = AccountStore(path, FixtureVault())
            first, second = [store.save(address, password='fixture', assignment={})
                for address in ('one@unit.invalid', 'two@unit.invalid')]
            for identifier, server, name in ((first, 384, 'One'), (second, 384, 'Two'), (first, 382, 'Another server')):
                store.save_characters(identifier, region='EU', server_id=server,
                    characters=[dict(index=0, key='628556622121157889', name=name)], observed_utc='2026-10-22T19:00:00+00:00')
            lists = AccountStore(path, FixtureVault()).character_lists()
            self.assertEqual(len(lists), 3)
            self.assertEqual(lists[first+'|EU|384']['characters'][0]['name'], 'One')
            self.assertEqual(lists[second+'|EU|384']['characters'][0]['name'], 'Two')
            self.assertEqual(lists[first+'|EU|382']['characters'][0]['key'], '628556622121157889')

    def test_only_accepted_list_replaces_cached_characters_and_empty_is_a_real_update(self):
        spec = importlib.util.spec_from_file_location('account_worker_cache_test', HERE / 'vampir-headless/account-worker.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('one@unit.invalid', password='fixture', assignment={})
            settings = dict(region='EU', server_id=384)
            accepted = dict(login_result_code=0, character_list_received=True, character_list_result_code=0,
                characters=[dict(index=0, key='11', name='One')])
            tool.remember_characters(store, identifier, settings, accepted)
            original = store.character_lists()
            for failed in ({}, dict(accepted, login_result_code=59), dict(accepted, character_list_received=False),
                           dict(accepted, character_list_result_code=9)):
                tool.remember_characters(store, identifier, settings, failed)
                self.assertEqual(store.character_lists(), original)
            tool.remember_characters(store, identifier, settings, dict(accepted, characters=[]))
            self.assertEqual(store.character_lists()[identifier+'|EU|384']['characters'], [])

    def test_invalid_character_update_preserves_previous_data(self):
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('one@unit.invalid', password='fixture', assignment={})
            record = dict(index=0, key='11', name='One')
            options = dict(region='EU', server_id=384, observed_utc='2026-10-22T19:00:00+00:00')
            store.save_characters(identifier, characters=[record], **options)
            original = store.character_lists()
            for rows in ([record, dict(record, index=1)], [dict(record, key=11)], [dict(record, index=True)],
                         [dict(record, name='bad\nlabel')]):
                with self.assertRaises(ValueError): store.save_characters(identifier, characters=rows, **options)
                self.assertEqual(store.character_lists(), original)

    def test_two_owned_workers_are_isolated_and_third_start_is_rejected(self):
        spec = importlib.util.spec_from_file_location('console_process_test', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'account-worker.py').write_text('import time\ntime.sleep(30)\n', encoding='utf-8')
            store = AccountStore(root / 'console.sqlite3', FixtureVault())
            ids = [store.save(f'worker{i}@unit.invalid', password='fixture', assignment={}) for i in range(3)]
            jobs = tool.Jobs(store)
            try:
                with patch.object(tool, 'HERE', root):
                    jobs.start(ids[0], 'start'); jobs.start(ids[1], 'start')
                    with self.assertRaises(ValueError): jobs.start(ids[2], 'start')
                self.assertNotEqual(jobs.jobs[ids[0]]['process'].pid, jobs.jobs[ids[1]]['process'].pid)
                jobs.stop(ids[0])
                self.assertIsNotNone(jobs.jobs[ids[0]]['process'].poll())
                self.assertIsNone(jobs.jobs[ids[1]]['process'].poll())
            finally:
                jobs.close()
                deadline = time.monotonic() + 3
                while any(j['running'] for j in jobs.snapshot().values()) and time.monotonic() < deadline:
                    time.sleep(.01)
            self.assertTrue(all(j['process'].poll() is not None for j in jobs.jobs.values()))

    def test_encrypted_password_is_never_returned_or_replaced_by_blank_form(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'console.sqlite3'
            store = AccountStore(path, FixtureVault())
            identifier = store.save('Bot@unit.invalid', password='private-password-fixture', assignment={'region': 'EU', 'server_id': 384})
            before = path.read_bytes()
            self.assertNotIn(b'private-password-fixture', before)
            self.assertEqual(store.save('bot@unit.invalid', assignment={'label': 'Основной'}), identifier)
            self.assertNotIn('private-password-fixture', json.dumps(store.accounts()))
            self.assertNotIn('password', {k for k in store.accounts()[0] if k != 'password_saved'})
            self.assertEqual(len(AccountStore(path, FixtureVault()).accounts()), 1)

    def test_assignments_validate_types_and_do_not_generate_identity(self):
        for value in ({'server_id': True}, {'character_index': -1}, {'device_profile': 'random-fingerprint'},
                      {'region': 'unknown'}, {'create_nickname': 'bad\nname'}, {'enabled': 1},
                      {'character_key': '999999999999999999999'}, {'character_key': '1'}, {'character_index': 0},
                      {'create_class': 'random'}, {'create_class': 3}, {'create_class': []}, {'create_random_nickname': 1},
                      {'auth_flow': 'signup'}, {'auth_flow': 'fallback'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                AccountStore.assignment(value)
        self.assertEqual(AccountStore.assignment({})['device_profile'], 'current-pc')

    def test_mail_password_and_registration_state_survive_blank_save(self):
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('fixture@vampir.top', password='game-fixture', mail_password='mail-fixture', assignment={})
            store.registration_status(identifier, 'registered')
            store.save('fixture@vampir.top', assignment={'enabled': False})
            row = store.accounts()[0]
            self.assertTrue(row['mail_password_saved'])
            self.assertFalse(row['enabled'])
            self.assertEqual(row['registration_status'], 'registered')
            self.assertNotIn(b'mail-fixture', store.path.read_bytes())

    def test_disabled_account_and_unapproved_registration_never_start_process(self):
        spec = importlib.util.spec_from_file_location('console_job_test', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('fixture@vampir.top', password='fixture', mail_password='fixture', assignment={'enabled': False})
            jobs = tool.Jobs(store)
            with patch.object(tool.subprocess, 'Popen') as popen:
                with self.assertRaises(ValueError): jobs.start(identifier, 'start')
                store.save('fixture@vampir.top', assignment={'enabled': True})
                with self.assertRaises(ValueError): jobs.start(identifier, 'register')
                store.registration_status(identifier, 'registered')
                with self.assertRaises(ValueError): jobs.start(identifier, 'register', accept_required_terms=True)
                popen.assert_not_called()

    def test_excluded_account_refuses_jobs_and_verification_while_reserve_allows_manual_work(self):
        spec = importlib.util.spec_from_file_location('console_device_use_modes', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'console.sqlite3', FixtureVault())
            identifier = store.save('fixture@vampir.top', password='fixture', mail_password='fixture',
                assignment={'device_type': 'Не использовать', 'enabled': True})
            jobs = tool.Jobs(store)
            with patch.object(tool.subprocess, 'Popen') as popen:
                for operation in ('servers', 'characters', 'start', 'create', 'prepare-sdk', 'register'):
                    with self.assertRaisesRegex(ValueError, 'Не использовать'):
                        jobs.start(identifier, operation)
                with self.assertRaises(ValueError):
                    jobs.verify_batch([identifier])
                popen.assert_not_called()
            store.save('fixture@vampir.top', assignment={'device_type': 'Не задействован', 'enabled': True})
            verifier = MagicMock()
            verifier.selected_profile.return_value = 'sdk-launcher:fixture'
            with patch.object(tool.subprocess, 'Popen') as popen, patch.object(tool.threading, 'Thread'):
                jobs.start(identifier, 'servers')
                self.assertIn('--operation', popen.call_args.args[0])
                self.assertIn('servers', popen.call_args.args[0])
                jobs.jobs[identifier]['running'] = False
                with patch.object(tool.importlib.util, 'spec_from_file_location'), \
                        patch.object(tool.importlib.util, 'module_from_spec', return_value=verifier):
                    jobs.verify_batch([identifier])
                self.assertIn('verify', popen.call_args.args[0])
                self.assertEqual(jobs.verification_snapshot()['active'], identifier)

    def test_registration_direct_release_requires_completion_and_closes_mailbox(self):
        spec = importlib.util.spec_from_file_location('registration_adapter_test', HERE / 'vampir-headless/register-nid-account.py')
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        runner, browser, mailbox = MagicMock(), MagicMock(), MagicMock()
        runner.load_inputs.return_value = (object(), {'game_code': 'thered'}, {})
        modules = {'run-nid-sdk-sign-in.py': runner, 'nid-browser.py': browser,
                   'nid-mail-code.py': SimpleNamespace(RegistrationMailbox=lambda *args: mailbox)}
        for completed in (False, True):
            def capture(*args, **kwargs):
                kwargs['progress']({'complete': completed})
                return 'fixture-provider'
            browser.capture_nid_credential.side_effect = capture
            with patch.object(tool, 'module', side_effect=lambda name, filename: modules[filename]), \
                 patch.object(tool, 'prepare_observed_profile') as prepare:
                options = dict(password='game-fixture', mail_password='mail-fixture', selected_profile='recovered-release',
                    socks_port=None, accept_required_terms=True, _progress=lambda state: None)
                if completed:
                    self.assertEqual(tool.run('fixture@vampir.top', **options), 'fixture-provider')
                else:
                    with self.assertRaises(RuntimeError): tool.run('fixture@vampir.top', **options)
                prepare.assert_called_once_with(runner, 'fixture@vampir.top', selected_profile='recovered-release')
                self.assertIsNone(runner.load_inputs.call_args.kwargs['route'])
                self.assertIsNone(browser.capture_nid_credential.call_args.kwargs['socks_port'])
        self.assertEqual(mailbox.close.call_count, 2)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows DPAPI')
    def test_real_dpapi_round_trip_and_wrong_ciphertext_fail(self):
        vault = WindowsVault()
        encrypted = vault.encrypt('fixture-only-Ж42')
        self.assertNotIn(b'fixture-only', encrypted)
        self.assertEqual(vault.decrypt(encrypted), 'fixture-only-Ж42')
        with self.assertRaises(RuntimeError):
            vault.decrypt(b'invalid-DPAPI-fixture')

    def test_http_token_origin_and_host_gate_with_fixture_data_only(self):
        spec = importlib.util.spec_from_file_location('account_console_test', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'accounts.sqlite3', FixtureVault())
            store.save('one@unit.invalid', password='fixture', assignment={})
            http, jobs = tool.server(store, port=0)
            worker = threading.Thread(target=http.serve_forever, daemon=True)
            worker.start()
            base = 'http://127.0.0.1:' + str(http.server_port)
            try:
                with urlopen(base) as response:
                    page = response.read().decode()
                    self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
                token = re.search(r'name="console-token" content="([^"]+)"', page)[1]
                for headers in ({}, {'X-Console-Token': token, 'Origin': 'https://unit.invalid'},
                                {'X-Console-Token': token, 'Host': 'unit.invalid'}):
                    with self.subTest(headers=list(headers)), self.assertRaises(HTTPError) as error:
                        urlopen(Request(base + '/api/state', headers=headers))
                    self.assertEqual(error.exception.code, 403)
                    error.exception.close()
                with urlopen(Request(base + '/api/state', headers={'X-Console-Token': token})) as response:
                    data = json.load(response)
                self.assertEqual(data['accounts'][0]['email'], 'one@unit.invalid')
                self.assertEqual(data['jobs'], {})
                self.assertNotIn('password', data['accounts'][0])
            finally:
                jobs.close(); http.shutdown(); http.server_close(); worker.join(3)

    def test_world_console_joins_two_owners_and_stops_only_the_selected_session(self):
        from vampir_core.live_session import LiveSession
        from vampir_core.live_session_server import LiveSessionServer
        spec = importlib.util.spec_from_file_location('console_world_fixture', HERE / 'vampir-headless/account-manager.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        import account_world

        with tempfile.TemporaryDirectory() as folder:
            store = AccountStore(Path(folder) / 'accounts.sqlite3', FixtureVault())
            assignment = dict(region='EU', server_id=387, character_index=0, character_key='42', auth_flow='launcher')
            first, second = [LiveSession(bot_id=store.save(email, password='fixture', assignment=assignment))
                             for email in ('first@unit.invalid', 'second@unit.invalid')]
            first._snapshot.update(state='connected', character=dict(key='42', name='Fixture', level=27),
                                   heartbeat=dict(sent=3, received=3))
            with LiveSessionServer(first, port=0) as owner, LiveSessionServer(second, port=0) as other, \
                    patch.object(account_world, 'BUILTIN_PORTS', (owner.server.server_port, other.server.server_port)):
                world = account_world.WorldControl(store)
                http, jobs = tool.server(store, port=0, world=world)
                worker = threading.Thread(target=http.serve_forever, daemon=True)
                worker.start()
                base = 'http://127.0.0.1:' + str(http.server_port)
                try:
                    with urlopen(base + '/world-map?bot=' + first.bot_id) as response:
                        page = response.read().decode()
                    self.assertIn('prototype-group.js', page)
                    token = re.search(r'name="console-token" content="([^"]+)"', page)[1]
                    headers = {'X-Console-Token': token, 'Content-Type': 'application/json'}
                    with urlopen(Request(base + '/api/world', headers=headers)) as response:
                        sessions = json.load(response)['sessions']
                    self.assertEqual(sessions[first.bot_id]['character']['level'], 27)
                    self.assertEqual(sessions[second.bot_id]['state'], 'connecting')
                    self.assertFalse(sessions[first.bot_id]['can_start'])
                    def stop(session_id):
                        body = dict(action='stop', id=first.bot_id, session_id=session_id)
                        return urlopen(Request(base + '/api/world', json.dumps(body).encode(), headers))
                    with self.assertRaises(HTTPError) as stale:
                        stop(second.session_id)
                    stale.exception.close()
                    self.assertFalse(first.stop_requested)
                    with stop(first.session_id) as response:
                        self.assertEqual(response.status, 202)
                    self.assertTrue(first.stop_requested)
                    self.assertFalse(second.stop_requested)

                    first.close()
                    called = threading.Event()
                    with patch.object(world, 'launch', side_effect=lambda *_: called.set()) as launch:
                        body = dict(action='start', id=first.bot_id)
                        with urlopen(Request(base + '/api/world', json.dumps(body).encode(), headers)) as response:
                            self.assertEqual(response.status, 202)
                        self.assertTrue(called.wait(2))
                        launch.assert_called_once()
                        with self.assertRaises(HTTPError) as duplicate:
                            urlopen(Request(base + '/api/world', json.dumps(body).encode(), headers))
                        duplicate.exception.close()
                    self.assertEqual(account_world.WorldControl(store).owners()[first.bot_id], launch.call_args.args[1])
                finally:
                    jobs.close(); http.shutdown(); http.server_close(); worker.join(3)


if __name__ == '__main__':
    unittest.main()
