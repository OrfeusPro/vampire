"""First-profile scope isolation, one attempt, source freshness and terminal forms."""
from contextlib import contextmanager, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core import sdk_first_profile_admission as admission
from vampir_core.gmc2_context import SdkInputs, Gmc2Geo, MAX_CONTEXT_AGE
from vampir_core.nid_result import NidEmailCredential
from vampir_core.sdk_fetch import SdkFetchSummary
from vampir_core.sdk_first_login import FirstSdkLoginStopped
from vampir_core.sdk_sign_in_response import SdkSignInData
from vampir_core.sdk_sign_up_response import SdkSignUpData
from vampir_core.sdk_sign_in_http import SdkSignInHttpError
from vampir_core.sdk_terms import BasicTermsSummary, IndividualTermsSummary

ROOT = Path('F:/PhoneExit Resources/Vampir')
WORKSPACE = HERE.parents[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class FirstSdkProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = load(HERE / 'resource-tools/vampir/build-sdk-first-profile.py', 'first_sdk_fixture_builder')
        cls.selector = json.loads((HERE / 'resource-tools/vampir/knowledge/sdk-first-profile-current.json').read_bytes())
        cls.profile = cls.builder.build(cls.selector['fetch_profile'], cls.selector['contracts'])
        cls.path = cls.builder.publish(cls.profile)
        cls.options = dict(root=ROOT, workspace=WORKSPACE, installed=cls.builder.INSTALLED)
        cls.provider = NidEmailCredential('fixture-provider-secret', '', 'fixture-nid', 'UA')

    def prepared(self, selector, *, old=False):
        sha = self.profile['source_sha256']
        return SdkInputs('fixture@vampir.top', SimpleNamespace(device_key='fixture-sdk', nm_device_key='fixture-nm'),
            dict(game_code='thered', build_code=2, country_code='UA', os_type='PC'),
            dict(authUrl='https://sdk.fixture.invalid/', termsUrl='https://terms-api.netmarble.com'),
            selector, None, sha, Gmc2Geo('1.1.1.1', 'UA', 'UA', 'fixture', sha),
            time.monotonic() - (MAX_CONTEXT_AGE + 1 if old else 0))

    def executors(self, *, challenge=True):
        return dict(_fetch=Mock(side_effect=SdkSignInHttpError('http_status', 400, 1203)) if challenge else Mock(return_value=SdkFetchSummary(True)),
            _terms=Mock(side_effect=[BasicTermsSummary('no_data', -1, 0), IndividualTermsSummary('no_data', -1)]),
            _signup=Mock(return_value=SdkSignUpData('fixture-player')),
            _signin=Mock(return_value=SdkSignInData('fixture-sdk-secret', 'fixture-player', 'EU', 'UA', 1, ())))

    def execute(self, inputs, executors, **kwargs):
        return admission.execute_first_profile(inputs, self.provider, terms_country='UA', terms_locale='ru-RU',
            basic_filtered=False, **executors, **kwargs)

    def test_complete_first_sequence_and_existing_profile_keep_old_guards_closed(self):
        for challenge in (True, False):
            executors = self.executors(challenge=challenge); stages = []
            with admission.scope(self.path.parent.name, **self.options) as (_, selector):
                inputs = self.prepared(selector)
                with self.assertRaises(ValueError): inputs.check_auth_operation(auth_flow='nid', first_sdk_login=True)
                signed = self.execute(inputs, executors, progress=stages.append)
                self.assertEqual(signed.player_id, 'fixture-player')
                self.assertEqual(executors['_signup'].call_count, int(challenge))
                self.assertEqual(executors['_terms'].call_count, 2 if challenge else 0)
                self.assertEqual(executors['_signin'].call_count, 1)
                self.assertEqual(stages[-1], 'sdk_sign_in')
                with self.assertRaisesRegex(ValueError, 'unused'): self.execute(inputs, executors)
                with self.assertRaises(ValueError):
                    with admission.scope(self.path.parent.name, **self.options): self.fail('Nested first profile')
            with self.assertRaises(ValueError): self.execute(inputs, executors)

    def test_only_fresh_fetch_challenge_reaches_terms_and_available_terms_stop(self):
        for sdk_code in (1202, 1204, None):
            executors = self.executors(); executors['_fetch'].side_effect = SdkSignInHttpError('http_status', 400, sdk_code)
            with admission.scope(self.path.parent.name, **self.options) as (_, selector):
                with self.assertRaises(SdkSignInHttpError): self.execute(self.prepared(selector), executors)
            executors['_terms'].assert_not_called(); executors['_signup'].assert_not_called()
        executors = self.executors(); executors['_terms'].side_effect = None
        executors['_terms'].return_value = BasicTermsSummary('terms_available', 0, 1)
        with admission.scope(self.path.parent.name, **self.options) as (_, selector):
            with self.assertRaisesRegex(FirstSdkLoginStopped, 'basic_terms_require_review'):
                self.execute(self.prepared(selector), executors)
        executors['_signup'].assert_not_called(); executors['_signin'].assert_not_called()

    def test_unknown_signup_never_retries_or_signs_in(self):
        executors = self.executors(); executors['_signup'].side_effect = TimeoutError('fixture')
        with admission.scope(self.path.parent.name, **self.options) as (_, selector):
            inputs = self.prepared(selector)
            with self.assertRaises(TimeoutError): self.execute(inputs, executors)
            with self.assertRaisesRegex(ValueError, 'unused'): self.execute(inputs, executors)
        self.assertEqual(executors['_signup'].call_count, 1); executors['_signin'].assert_not_called()

    def test_expired_or_patched_client_stops_before_mutating_request(self):
        executors = self.executors()
        with admission.scope(self.path.parent.name, **self.options) as (_, selector):
            with self.assertRaisesRegex(ValueError, 'expired'): self.execute(self.prepared(selector, old=True), executors)
            executors['_fetch'].assert_not_called()
            changed = [False]; real_digest = admission.digest
            def digest(path):
                return '0' * 64 if changed[0] and Path(path) == self.builder.INSTALLED else real_digest(path)
            def progress(stage):
                if stage == 'sdk_individual_terms': changed[0] = True
            with patch.object(admission, 'digest', side_effect=digest):
                with self.assertRaisesRegex(ValueError, 'client changed'):
                    self.execute(self.prepared(selector), executors, progress=progress)
        executors['_signup'].assert_not_called(); executors['_signin'].assert_not_called()

    def test_profile_validates_exact_manifest_and_retained_web_helpers(self):
        loaded = admission.load_manifest(self.path.parent.name, **self.options)
        self.assertEqual(loaded['operations'], admission.OPERATIONS)
        self.assertFalse(loaded['game_session_ready'])
        with self.assertRaises(ValueError): admission.load_manifest('short', **self.options)
        real_digest = admission.digest
        def corrupted(path):
            return '0' * 64 if Path(path).name == 'verification-form.js' else real_digest(path)
        with patch.object(admission, 'digest', side_effect=corrupted):
            with self.assertRaisesRegex(ValueError, 'verification helper changed'):
                admission.load_manifest(self.path.parent.name, **self.options)

    def test_cached_update_receipt_cannot_drop_retained_source_inputs(self):
        guard=load(HERE/'resource-tools/vampir/sdk-first-profile-check-guard.py','first_sdk_source_guard_fixture')
        pointer=dict(path='fixture-profile',sha256='a'*64)
        report=dict(definition=dict(check=dict(id='sdk-first-profile-runtime'),
            source_sha256=self.profile['source_sha256'],artifacts={}),sdk_first_profile_guard=dict(pointer=pointer))
        index=SimpleNamespace(KNOWLEDGE=HERE,INSTALL=self.builder.INSTALLED)
        with patch.object(guard,'retained',return_value=({'fixture-retained-input':'b'*64},pointer)):
            with self.assertRaisesRegex(ValueError,'lost a retained input'):
                guard.runtime_inputs(index,ROOT,report,'sdk-first-profile-runtime')
            report['definition']['artifacts']['fixture-retained-input']='b'*64
            self.assertEqual(guard.runtime_inputs(index,ROOT,report,'sdk-first-profile-runtime'),{})


class FirstSdkCommandTests(unittest.TestCase):
    def test_nid_failure_retains_only_the_existing_safe_diagnostics(self):
        module=load(HERE/'vampir-headless/run-account-first-sdk.py','first_sdk_nid_diagnostic_fixture')
        browser=module.load('nid-browser')
        error=browser.NidBrowserStatusError('login_failed','submitted',400,None,'no_numeric_code','captcha_required','message_only')
        error.untrusted_text='fixture-private-secret'
        result=module.nid_failure(error)
        self.assertEqual(result['nid_error_hint'],'captcha_required')
        self.assertEqual(result['nid_http_status'],400)
        self.assertNotIn('untrusted_text',result)
        self.assertNotIn('fixture-private-secret',json.dumps(result))

    def test_account_lease_blocks_duplicates_and_releases_after_exception(self):
        module = load(HERE / 'vampir-headless/run-account-first-sdk.py', 'first_sdk_command_lease_fixture')
        account = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as folder:
            with module.account_lease(account, Path(folder)):
                with self.assertRaisesRegex(RuntimeError, 'owner'):
                    with module.account_lease(account, Path(folder)): self.fail('Second owner')
            with module.account_lease(account, Path(folder)): pass
            with self.assertRaises(ValueError):
                with module.account_lease('../escape', Path(folder)): self.fail('Invalid path')

    def test_terminal_forms_receive_same_sdk_context_and_never_reauthenticate(self):
        module = load(HERE / 'vampir-headless/run-account-first-sdk.py', 'first_sdk_command_flow_fixture')
        account = str(uuid.uuid4()); events = []; password = 'fixture-private-password'
        settings = dict(enabled=True, socks_port=None, device_settings={}, device_name='DESKTOP-FIXTURE')
        prepared = SimpleNamespace(binding=SimpleNamespace(device_key='fixture-device', nm_device_key='fixture-nm', nid_device_key='fixture-nid'),
            constants=dict(termsUrl='https://terms-api.netmarble.com'), profile=dict(game_code='thered', os_type='PC'),
            geo=SimpleNamespace(iso_country='UA'))
        signed = SdkSignInData('fixture-sdk-token-secret', 'fixture-player', 'EU', 'UA', 1, ('device-registration','workplace'))
        store = SimpleNamespace(credential=lambda _: ('fixture@vampir.top', password, settings),
            _fingerprint=lambda _: 'fixture-fingerprint', accounts=lambda: [dict(id=account, **settings)],
            registration_status=lambda *_: events.append('sdk_status'), reveal_password=lambda *_: 'fixture-mail-secret',
            record_device_verification=lambda *_: True)
        verifier = SimpleNamespace(ensure_pc_binding=lambda *_: None)
        def verify(**kwargs):
            self.assertIs(kwargs['prepared'], prepared); self.assertIs(kwargs['data'], signed)
            self.assertFalse(kwargs['require_fresh_context']); events.append('verification')
            return 'verified', ['device-registration','workplace']
        verifier.continue_verification = verify
        runner = SimpleNamespace(load_inputs=lambda *_a,**_k: prepared)
        browser = SimpleNamespace(capture_nid_credential=Mock(return_value=object()), NidBrowserStatusError=type('FixtureNidError',(RuntimeError,),{}))
        @contextmanager
        def scope(*_a,**_k): yield {}, 'fixture-selector'
        def execute(*_a,**kwargs):
            for stage in ('sdk_fetch_player','sdk_basic_terms','sdk_individual_terms','sdk_first_profile','sdk_sign_in'):
                kwargs['progress'](stage)
            return signed
        with tempfile.TemporaryDirectory() as folder, patch.object(module,'HERE',Path(folder)), \
                patch.object(module,'AccountStore',Mock(return_value=store)) as constructor, \
                patch.object(module,'scope',scope), patch.object(module,'execute_first_profile',execute), \
                patch.object(module,'prepare_nid_sign_in_context',return_value=object()), \
                patch.object(module,'bind_nid_web_url',return_value=object()), \
                patch.object(module,'load',side_effect=lambda name: {'run-nid-sdk-sign-in':runner,'nid-browser':browser,'verify-account':verifier}[name]):
            constructor.assignment.side_effect=lambda x:x
            output=io.StringIO()
            with redirect_stdout(output):
                result=module._run(account,'a'*64,terms_country='observed',terms_locale='ru-RU',
                    basic_filtered=False,timeout=1,capture_sdk_http=False)
            self.assertTrue(result['accepted']); self.assertTrue(result['sdk_profile_created'])
            self.assertEqual(events,['sdk_status','verification'])
            self.assertEqual(browser.capture_nid_credential.call_count,1)
            for secret in (password,'fixture-sdk-token-secret','fixture-mail-secret'):
                self.assertNotIn(secret, output.getvalue())


if __name__ == '__main__': unittest.main()
