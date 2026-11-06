"""Fetch-only admission, failure ownership and original scope isolation."""
import importlib.util
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core import sdk_fetch_admission as admission
from vampir_core.gmc2_context import SdkInputs, Gmc2Geo, MAX_CONTEXT_AGE
from vampir_core.nid_result import NidEmailCredential
from vampir_core.sdk_fetch import SdkFetchSummary
from vampir_core.sdk_sign_in_http import SdkSignInHttpError

ROOT = Path('F:/PhoneExit Resources/Vampir')
WORKSPACE = HERE.parents[1]
CONTRACT = ROOT / 'code-clues/sdk-fetch-current-static-v1/23114d06e04c062262d66634d95e419b12d017c0da70e08133b51fdda472df46/manifest.json'


class FetchAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = HERE / 'resource-tools/vampir/build-sdk-fetch-profile.py'
        spec = importlib.util.spec_from_file_location('fetch_fixture_profile_builder', path)
        cls.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.builder)
        cls.profile = cls.builder.build(CONTRACT)
        cls.manifest = cls.builder.publish(cls.profile)
        cls.options = dict(root=ROOT, workspace=WORKSPACE, installed=cls.builder.INSTALLED)

    def prepared(self, selector, *, old=False):
        sha = self.profile['source_sha256']
        return SdkInputs('fixture@vampir.top', SimpleNamespace(device_key='sdk-fixture', nm_device_key='nm-fixture'),
            dict(game_code='thered', build_code=2, country_code='UA', os_type='Windows'),
            dict(authUrl='https://sdk.fixture.invalid/'), selector, None, sha,
            Gmc2Geo('1.1.1.1', 'UA', 'UA', 'fixture', sha),
            time.monotonic() - (MAX_CONTEXT_AGE + 1 if old else 0))

    def test_profile_rechecks_current_source_inputs_and_exact_operation(self):
        loaded = admission.load_manifest(self.manifest.parent.name, **self.options)
        self.assertEqual(loaded, self.profile)
        self.assertEqual(loaded['operations'], ['v1/fetch-player'])
        self.assertFalse(loaded['game_session_ready'])
        real_digest = admission.digest
        def changed(path):
            return '0' * 64 if Path(path).resolve() == Path(admission.__file__).resolve() else real_digest(path)
        with patch.object(admission, 'digest', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'loader is not retained'):
                admission.load_manifest(self.manifest.parent.name, **self.options)
        with self.assertRaises(ValueError):
            admission.load_manifest('bad-short-selector', **self.options)

    def test_one_fetch_keeps_body_narrow_and_does_not_expand_launcher_guards(self):
        provider = NidEmailCredential('fixture-provider-token', '', 'fixture-nid-account', 'UA')
        executor = Mock(return_value=SdkFetchSummary(True))
        with admission.scope(self.manifest.parent.name, **self.options) as (_, selector):
            inputs = self.prepared(selector)
            with self.assertRaises(ValueError):
                inputs.check_auth_operation(auth_flow='nid', fetch_player=True)
            result = admission.execute_fetch(inputs, provider, _execute=executor)
            self.assertTrue(result.result_object_present)
            plan = executor.call_args.args[0]
            self.assertTrue(plan.url.endswith('/v1/fetch-player'))
            self.assertEqual(json.loads(plan.body), dict(scope='channel', credential=dict(
                channelCode=33, channelAccessToken='fixture-provider-token')))
            with self.assertRaisesRegex(ValueError, 'unused'):
                admission.execute_fetch(inputs, provider, _execute=executor)
            with self.assertRaises(ValueError):
                with admission.scope(self.manifest.parent.name, **self.options):
                    self.fail('Nested Fetch must fail')
        self.assertEqual(executor.call_count, 1)
        with self.assertRaises(ValueError):
            admission.execute_fetch(inputs, provider, _execute=executor)

    def test_error_consumes_exchange_and_stale_context_never_calls_transport(self):
        provider = NidEmailCredential('fixture-provider-token', '', 'fixture-nid-account', 'UA')
        executor = Mock(side_effect=SdkSignInHttpError('http_status', 400, 1203))
        with admission.scope(self.manifest.parent.name, **self.options) as (_, selector):
            with self.assertRaisesRegex(ValueError, 'expired'):
                admission.execute_fetch(self.prepared(selector, old=True), provider, _execute=executor)
            executor.assert_not_called()
            with self.assertRaises(SdkSignInHttpError):
                admission.execute_fetch(self.prepared(selector), provider, _execute=executor)
            with self.assertRaisesRegex(ValueError, 'unused'):
                admission.execute_fetch(self.prepared(selector), provider, _execute=executor)
        self.assertEqual(executor.call_count, 1)

    def test_cached_source_guard_refuses_missing_retained_evidence(self):
        path = HERE / 'resource-tools/vampir/sdk-fetch-check-guard.py'
        spec = importlib.util.spec_from_file_location('fetch_cache_guard_fixture', path)
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        pointer = dict(path='fixture-report', sha256='f' * 64)
        definition = dict(id='sdk-fetch-read-runtime')
        report = dict(definition=dict(check=definition, source_sha256=self.profile['source_sha256'],
            artifacts={}), sdk_fetch_guard=dict(pointer=pointer))
        with patch.object(guard, 'retained', return_value=({'fixture-input': 'e' * 64}, pointer)):
            with self.assertRaisesRegex(ValueError, 'lost a retained input'):
                guard.runtime_inputs(SimpleNamespace(KNOWLEDGE=HERE), ROOT, report, definition['id'])
        report['definition']['artifacts']['fixture-input'] = 'e' * 64
        index = SimpleNamespace(KNOWLEDGE=HERE, INSTALL=self.builder.INSTALLED)
        with patch.object(guard, 'retained', return_value=({'fixture-input': 'e' * 64}, pointer)):
            self.assertEqual(guard.runtime_inputs(index, ROOT, report, definition['id']), {})


if __name__ == '__main__':
    unittest.main()
