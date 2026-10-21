"""Fresh public fetch -> one SDK context; all HTTP/browser/account work mocked."""
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


class Gmc2RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'vampir-headless/run-nid-sdk-sign-in.py'
        spec=importlib.util.spec_from_file_location('gmc2_runtime_test_runner',path)
        cls.tool=importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.tool)

    def test_current_profile_fetches_one_body_for_constants_and_geo_without_snapshot_replay(self):
        binding=SimpleNamespace(kind='real',identity_recorded=True,nid_identity_recorded=True,confirmation='unknown',
            device_key='sdk-fixture',nid_device_key='nid-fixture',nm_device_key='nm-fixture')
        identity=SimpleNamespace(device_key=binding.device_key,nid_device_key=binding.nid_device_key,nm_device_key=binding.nm_device_key)
        body=json.dumps(dict(errorCode=0,resultData=dict(geoIp=dict(clientIp='1.1.1.1',geoLocation='JP',isoCountry='HK')))).encode()
        transport=dict(status=200,tls_certificate_verification=True,socks5_loopback_port=17948,headers=[])
        route=self.tool.SocksRoute(17948)
        with patch.object(self.tool,'DeviceRegistry') as registry, \
                patch.object(self.tool,'observe_windows_device_identity',return_value=identity), \
                patch.object(self.tool,'observe_windows_version',return_value=None), \
                patch.object(self.tool,'fetch_gmc2',return_value=(body,transport)) as fetch, \
                patch.object(self.tool,'decode_gmc2_configuration',return_value=SimpleNamespace(constants={'key':'fixture'})) as decode:
            registry.return_value.get.return_value=binding
            result=self.tool.load_inputs('fixture@example.invalid',route=route,selected_profile='recovered-release')
        self.assertIsInstance(result,self.tool.SdkInputs)
        self.assertEqual(result.route_port,17948)
        self.assertEqual(result.profile['country_code'],'HK')
        self.assertEqual(result.geo.metadata(previous_country='')['I_CountryCD'],'JP')
        self.assertEqual(result.geo.body_sha256,hashlib.sha256(body).hexdigest())
        self.assertEqual(result.constants,{'key':'fixture'})
        self.assertIs(decode.call_args.args[0],body)
        fetch.assert_called_once()
        self.assertIs(fetch.call_args.kwargs['route'],route)
        self.assertEqual(dict(fetch.call_args.args[0]['headers'])['nmDeviceKey'],'')

    def prepared(self):
        from vampir_core.gmc2_context import Gmc2Geo, SOURCE_SHA256
        from vampir_core.device_registry import DeviceBinding
        from vampir_core.nid_result import NidEmailCredential
        binding=DeviceBinding('fixture@example.invalid','fixture-profile','real',True,
            'sdk-fixture','nm-fixture','fixture-source','unknown','','nid-fixture','fixture-nid-source')
        profile=dict(game_code='thered',client_id='client-fixture',build_code=0,os_type='PC',
            raw_webview_type=0,country_code='HK',language='en',os_version='')
        constants=dict(authWebViewUrl='https://members.netmarble.com/auth',authUrl='https://sdk.example.invalid')
        inputs=self.tool.SdkInputs('fixture@example.invalid',binding,profile,constants,'recovered-release',17948,
            SOURCE_SHA256,Gmc2Geo('1.1.1.1','JP','HK','fixture-body-sha'),100)
        return inputs,NidEmailCredential('provider-fixture','','nid-account-fixture','HK')

    def test_prepared_context_is_reused_without_refetch_or_second_load(self):
        inputs,provider=self.prepared()
        with patch.object(self.tool,'load_inputs',side_effect=AssertionError('must reuse')), \
                patch.object(self.tool.time,'monotonic',return_value=100):
            result=self.tool.run(inputs.email,selected_profile='recovered-release',socks_port=17948,
                _prepared_inputs=inputs,_capture=lambda *a,**k:provider,_execute=lambda *a,**k:'accepted-fixture')
        self.assertEqual(result,'accepted-fixture')

    def test_expiry_during_browser_rejects_before_sdk_post(self):
        inputs,provider=self.prepared(); execute=Mock()
        with patch.object(self.tool.time,'monotonic',return_value=100) as clock:
            def capture(*a,**k):
                clock.return_value=401
                return provider
            with self.assertRaisesRegex(ValueError,'expired'):
                self.tool.run(inputs.email,selected_profile='recovered-release',socks_port=17948,
                    _prepared_inputs=inputs,_capture=capture,_execute=execute)
        execute.assert_not_called()

    def test_wrong_prepared_route_rejects_before_browser(self):
        inputs,_=self.prepared(); capture=Mock(); execute=Mock()
        with patch.object(self.tool.time,'monotonic',return_value=100):
            with self.assertRaisesRegex(ValueError,'differs'):
                self.tool.run(inputs.email,selected_profile='recovered-release',socks_port=17949,
                    _prepared_inputs=inputs,_capture=capture,_execute=execute)
        capture.assert_not_called(); execute.assert_not_called()

    def test_bad_public_response_never_starts_browser_or_sdk_authentication(self):
        inputs,_=self.prepared(); binding=inputs.binding
        identity=SimpleNamespace(device_key=binding.device_key,nid_device_key=binding.nid_device_key,nm_device_key=binding.nm_device_key)
        good=dict(status=200,tls_certificate_verification=True,socks5_loopback_port=17948,headers=[])
        capture=Mock(); execute=Mock()
        for body,transport in ((b'{}',good),(b'{}',{**good,'status':500}),
                               (b'{}',{**good,'tls_certificate_verification':False}),
                               (b'{}',{**good,'socks5_loopback_port':17949})):
            with self.subTest(status=transport['status']), \
                    patch.object(self.tool,'DeviceRegistry') as registry, \
                    patch.object(self.tool,'observe_windows_device_identity',return_value=identity), \
                    patch.object(self.tool,'fetch_gmc2',return_value=(body,transport)), \
                    patch.object(self.tool,'decode_gmc2_configuration') as decode:
                registry.return_value.get.return_value=binding
                with self.assertRaises(ValueError):
                    self.tool.run(inputs.email,selected_profile='recovered-release',socks_port=17948,
                        _capture=capture,_execute=execute)
                decode.assert_not_called()
        capture.assert_not_called(); execute.assert_not_called()


if __name__ == '__main__': unittest.main()
