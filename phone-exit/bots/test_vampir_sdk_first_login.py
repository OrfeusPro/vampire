"""First SDK profile orchestration with deterministic transports, never live auth."""
import io
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
import unittest
import urllib.error

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.nid_sdk_credential import NidSdkCredential
from vampir_core.sdk_fetch import SdkFetchSummary
from vampir_core.sdk_sign_in_http import SdkSignInHttpError, execute_sdk_fetch
from vampir_core.sdk_sign_up_response import SdkSignUpData
from vampir_core.sdk_sign_in_response import SdkSignInData
from vampir_core.sdk_first_login import execute_first_sdk_login, FirstSdkLoginStopped
from vampir_core.sdk_terms import (BasicTermsSummary, IndividualTermsSummary, BasicTermsReadPlan,
                                  plan_basic_terms_read, plan_individual_terms_read)
from vampir_core.sdk_terms_http import execute_terms_read, TermsReadError


FIELDS = ('title', 'url', 'required', 'contentExists', 'useAgree', 'useNotice',
          'agreeNotice', 'disagreeNotice', 'termsCode', 'imageContent')


class Response(io.BytesIO):
    def __init__(self, body, status=200, headers=None):
        super().__init__(body)
        self.status, self.headers = status, headers or {}


class FirstSdkLoginTests(unittest.TestCase):
    def inputs(self):
        return dict(constants={'authUrl': 'https://sdk.example.invalid', 'termsUrl': 'https://terms-api.netmarble.com'},
                    game_code='thered', build_code=0, nm_device_key='nm-fixture', device_key='device-fixture',
                    country_code='UA', os_type='PC')

    def flow(self, **overrides):
        events = []
        def fetch(plan, **kwargs):
            events.append('fetch')
            self.assertEqual(json.loads(plan.body)['scope'], 'channel')
            raise SdkSignInHttpError('http_status', 400, 1203)
        def terms(plan, **kwargs):
            events.append('basic' if type(plan) is BasicTermsReadPlan else 'individual')
            return BasicTermsSummary('no_data', -1, 0) if type(plan) is BasicTermsReadPlan else IndividualTermsSummary('no_data', -1)
        def signup(plan, **kwargs):
            events.append('signup')
            self.assertTrue(plan.url.endswith('/v1/sign-up'))
            self.assertEqual(json.loads(plan.body)['credential']['channelCode'], 33)
            return SdkSignUpData('new-player-fixture')
        def signin(plan, **kwargs):
            events.append('signin')
            self.assertTrue(plan.url.endswith('/v1/sign-in'))
            return SdkSignInData('sdk-token-fixture', 'new-player-fixture', None, None, 1)
        options = dict(credential=NidSdkCredential('nid-token-fixture'), inputs=self.inputs(),
                       terms_country='UA', terms_locale='en-US', basic_filtered=False,
                       _fetch=fetch, _terms=terms, _signup=signup, _signin=signin)
        options.update(overrides)
        return events, lambda: execute_first_sdk_login(**options)

    def test_exact_challenge_absent_terms_signup_then_signin(self):
        stages, contexts = [], []
        events, run = self.flow(progress=stages.append, check_context=lambda: contexts.append(True))
        self.assertEqual(run().player_id, 'new-player-fixture')
        self.assertEqual(events, ['fetch', 'basic', 'individual', 'signup', 'signin'])
        self.assertEqual(stages, ['sdk_fetch_player', 'sdk_basic_terms', 'sdk_individual_terms', 'sdk_first_profile', 'sdk_sign_in'])
        self.assertEqual(len(contexts), 5)

    def test_existing_profile_signs_in_without_terms_or_creation(self):
        events, run = self.flow(_fetch=lambda *a, **k: SdkFetchSummary(True))
        self.assertEqual(run().player_id, 'new-player-fixture')
        self.assertEqual(events, ['signin'])

    def test_other_failures_never_create(self):
        for error in (SdkSignInHttpError('http_status', 403, 1203), SdkSignInHttpError('http_status', 400, 42),
                      SdkSignInHttpError('transport_error'), SdkSignInHttpError('sdk_response_rejected', 200, 1203)):
            def fetch(*a, **k): raise error
            events, run = self.flow(_fetch=fetch)
            with self.assertRaises(SdkSignInHttpError): run()
            self.assertEqual(events, [])

    def test_available_or_empty_terms_stop_before_creation(self):
        for basic in (True, False):
            for state in ('terms_available', 'empty'):
                def terms(plan, **kwargs):
                    if type(plan) is BasicTermsReadPlan:
                        return BasicTermsSummary(state, 0, 0) if basic else BasicTermsSummary('no_data', -1, 0)
                    return IndividualTermsSummary(state, 0)
                events, run = self.flow(_terms=terms)
                with self.assertRaises(FirstSdkLoginStopped): run()
                self.assertEqual(events, ['fetch'])

    def test_unknown_creation_never_retries_or_signs_in(self):
        attempts = []
        def signup(*a, **k):
            attempts.append(True)
            raise SdkSignInHttpError('transport_error')
        events, run = self.flow(_signup=signup)
        with self.assertRaises(SdkSignInHttpError): run()
        self.assertEqual(len(attempts), 1)
        self.assertEqual(events, ['fetch', 'basic', 'individual'])

    def test_missing_explicit_query_stops_before_fetch(self):
        for options in (dict(terms_country=None), dict(terms_locale=None), dict(basic_filtered=None)):
            events, run = self.flow(**options)
            with self.assertRaises(ValueError): run()
            self.assertEqual(events, [])

    def test_signin_cannot_replace_the_new_player(self):
        events, run = self.flow(_signin=lambda *a, **k: SdkSignInData('fixture-token', 'other-player', None, None, 1))
        with self.assertRaisesRegex(FirstSdkLoginStopped, 'sdk_sign_in_player_mismatch'): run()
        self.assertEqual(events, ['fetch', 'basic', 'individual', 'signup'])

    def test_real_fetch_http_boundary_only_keeps_valid_numeric_challenge(self):
        from vampir_core.sdk_fetch import plan_nid_sdk_fetch
        plan = plan_nid_sdk_fetch(credential=NidSdkCredential('nid-token-fixture'), **self.inputs())
        for body, code in ((b'{"errorCode":"1203"}', 1203), (b'{"errorCode":1203}', 1203),
                           (b'{"errorCode":1203,"errorCode":42}', None),
                           (b'{"errorCode":1203,"x":NaN}', None),
                           (b'{"errorCode":true}', None), (b'{"errorCode":"01203"}', None)):
            def open(request, timeout):
                raise urllib.error.HTTPError(plan.url, 400, 'fixture', {}, io.BytesIO(body))
            with self.assertRaises(SdkSignInHttpError) as raised:
                execute_sdk_fetch(plan, expected_url=plan.url, _open=open)
            self.assertEqual(raised.exception.sdk_code, code)

    def test_current_source_fetch_constructor_signup_and_success_handoff(self):
        tools = Path(__file__).parent / 'resource-tools/vampir'
        spec = importlib.util.spec_from_file_location('first_sdk_source', tools / 'build-native-entry-code.py')
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        sha = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
        raw = (native.ROOT / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), sha)
        image = native.Image(raw)
        folder = native.ROOT / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details'
        for run, digest in (
            ('run-3380a52fff6d', '7b0307a30a6cc0b33c1149c956e12a0c822fa8f54a6b4299fbd07c429ad518aa'),
            ('run-8c0479e8b8bd', 'c0e9b7937e1d716ecbf03759a5449a60a2f7e4e7fee46fda852643067b4d1cd5'),
            ('run-313ff5f10ab1', 'd376e82c676025619f3973f6ba86389e192bb85b48223a76d46529d9b914756e'),
            ('run-429315d23bfb', '05607a1578f1907e7033e4a3708bee08ed0b64d9f3a13263dd6928f837e65522')):
            data = (folder / run / 'details.json').read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            report = json.loads(data)
            self.assertEqual(report['new_source_sha256'], sha)
            for function in report['functions']:
                self.assertTrue(function['decompilation_completed'])
                for row in function['instructions']:
                    code = bytes.fromhex(row['bytes'])
                    offset = image.offset(int(row['address'], 16) - image.pe.base)
                    self.assertEqual(raw[offset:offset + len(code)], code)
        offset = image.offset(0x141639d50 - image.pe.base)
        self.assertEqual(raw[offset:offset + 5], bytes.fromhex('0fb64120c3'))
        self.assertEqual(0 + 0x1ca86d0 + 0x1b, 30050027)


class TermsHttpTests(unittest.TestCase):
    def plan(self, individual=False):
        inputs = dict(constants={'termsUrl': 'https://terms-api.netmarble.com'}, game_code='thered',
                      country='UA', locale='en-US', platform='PC')
        return plan_individual_terms_read(**inputs, terms_name='terms_of_service_ko') if individual else plan_basic_terms_read(**inputs, filtered=False)

    def test_anonymous_gets_and_distinct_shapes(self):
        for individual in (False, True):
            body = json.dumps(dict(resultCode=-1, resultData={'terms': dict.fromkeys(FIELDS) if individual else []})).encode()
            calls = []
            response = Response(body)
            def open(request, timeout):
                calls.append(request)
                self.assertEqual(request.method, 'GET')
                self.assertIsNone(request.data)
                self.assertEqual(set(dict(request.header_items())), {'Accept', 'Accept-encoding', 'User-agent'})
                return response
            result = execute_terms_read(self.plan(individual), _open=open)
            self.assertEqual(result.state, 'no_data')
            self.assertFalse(result.consent_confirmed)
            self.assertEqual(len(calls), 1)
            self.assertTrue(response.closed)

    def test_failure_size_encoding_and_timeout(self):
        for response in (Response(b'{}', 302), Response(b'x' * 524289), Response(b'{}', headers={'Content-Encoding': 'gzip'}),
                         Response(b'{}', headers={'Content-Length': '3'}), Response(b'{}', headers={'Content-Length': 'invalid'}),
                         Response(b'{}', headers={'Content-Length': '524289'})):
            with self.assertRaises(TermsReadError):
                execute_terms_read(self.plan(), _open=lambda *a, **k: response)
            self.assertTrue(response.closed)
        ticks = iter((0, 31))
        with self.assertRaises(TermsReadError):
            execute_terms_read(self.plan(), _open=lambda *a, **k: Response(b'{}'), _clock=lambda: next(ticks))

    def test_invalid_individual_body_and_foreign_plan_stop(self):
        calls = []
        with self.assertRaises(ValueError):
            execute_terms_read(BasicTermsReadPlan('https://example.org/game/v2/thered/terms?country=UA&locale=en-US&platform=PC'),
                               _open=lambda *a, **k: calls.append(True))
        self.assertEqual(calls, [])
        for terms in ([], {}, dict.fromkeys(FIELDS, 'unexpected-content')):
            body = json.dumps(dict(resultCode=-1, resultData={'terms': terms})).encode()
            with self.assertRaises(ValueError):
                execute_terms_read(self.plan(True), _open=lambda *a, **k: Response(body))


if __name__ == '__main__': unittest.main()
