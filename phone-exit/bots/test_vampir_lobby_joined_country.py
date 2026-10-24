import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import unittest
import time


class LobbyJoinedCountryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'vampir-headless/probe-lobby-sdk-login.py'
        spec=importlib.util.spec_from_file_location('lobby_joined_country_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)

    def exercise(self,context,*,sdk_country='HK',nid_country='HK',release=False,device_settings=None):
        provider=SimpleNamespace(netmarble_id='nid-fixture',joined_country_code=nid_country)
        binding=SimpleNamespace(nm_device_key='nm-fixture',device_key='device-fixture')
        sdk_data=SimpleNamespace(player_id='player-fixture',access_token='token-fixture',joined_country_code=sdk_country)
        from vampir_core.gmc2_context import SdkInputs, Gmc2Geo
        prepared = SdkInputs('fixture@example.invalid', binding, {'game_code':'thered'}, {},
            'recovered-release', 17948, self.tool.METADATA_TID_SOURCE_SHA256,
            Gmc2Geo('1.1.1.1','JP','HK','fixture-body-sha'), time.monotonic()) if release else (binding,{'game_code':'thered'},{})
        def sdk_run(email,**kwargs):
            if release: self.assertIs(kwargs['_prepared_inputs'],prepared)
            kwargs['_capture']('https://example.invalid');return sdk_data
        modules=[SimpleNamespace(load_profile=lambda **k:SimpleNamespace(app_version='fixture',source_snapshot_sha256='fixture-snapshot',
            source_exe_sha256=self.tool.METADATA_TID_SOURCE_SHA256 if release else '')),
            SimpleNamespace(selected_endpoint=lambda *a,**k:('lobby.example',12000)),
            SimpleNamespace(load_inputs=lambda *a,**k:prepared,run=sdk_run),
            SimpleNamespace(capture_nid_credential=lambda *a,**k:provider),
            SimpleNamespace(prepare_version=lambda **k:object(),observe_computer_name=lambda:'fixture')]
        exchange=Mock(return_value=SimpleNamespace(summary={},response=SimpleNamespace(result_code=0)))
        consumer=Mock()
        with patch.object(self.tool,'module',side_effect=modules),patch.object(self.tool,'SocksRoute') as route, \
                patch.object(self.tool,'observe_windows_version',return_value=None),patch.object(self.tool,'exchange_lobby_login',exchange), \
                patch.object(self.tool,'resolve_metadata_tid',return_value='0123456789ABCDEFFEDCBA9876543210') as tid:
            route.return_value.port = 17948
            if context in ('sdk-with-joined-country','sdk-with-partial-metadata') and (sdk_country!=nid_country or sdk_country in (None,'hk','')):
                with self.assertRaises(ValueError):
                    self.tool.run('fixture@example.invalid',selected_profile='recovered-release' if release else 'recovered-base',manifest_path=Path('fixture'),
                        socks_port=17948,context=context)
                route.return_value.connect.assert_not_called();exchange.assert_not_called();return
            result=self.tool.run('fixture@example.invalid',selected_profile='recovered-release' if release else 'recovered-base',manifest_path=Path('fixture'),
                socks_port=17948,context=context,_consume_auth=consumer,device_settings=device_settings)
            self.assertEqual(tid.call_count, int(release and context=='sdk-with-partial-metadata'))
        login=exchange.call_args.args[2]
        self.assertEqual(login.strings[:5],('player-fixture','token-fixture','nm-fixture',
            sdk_country if context!='sdk-without-nid-info' else '', 'nid-fixture'))
        if context=='sdk-with-partial-metadata':
            import json
            fields=json.loads(login.strings[5])
            expected=dict(I_GameCode='thered',I_GameVersion='fixture',I_PID='player-fixture',
                I_JoinedCountryCode='HK',I_NMDeviceKey='nm-fixture',I_DeviceKey='device-fixture')
            if release:
                expected.update(I_TID='0123456789ABCDEFFEDCBA9876543210',I_ConnectIP='1.1.1.1',I_CountryCD='JP')
            if device_settings:
                from vampir_core.bot_device_settings import metadata_values
                expected.update(metadata_values(device_settings))
            self.assertEqual(fields,expected)
            self.assertEqual(result.summary['metadata_bytes'],len(login.strings[5].encode()))
            self.assertNotIn('player-fixture',str(result.summary))
        else:self.assertEqual(login.strings[5],'')
        self.assertEqual(login.integers,(2,0,0,0));self.assertEqual(login.raw_80,7)
        self.assertEqual(consumer.call_args.kwargs.get('nid_metadata',''),login.strings[5])
        self.assertNotIn('token-fixture',str(result.summary))
        route.return_value.connect.return_value.close.assert_called_once()

    def test_explicit_country_comes_from_matching_fresh_auth(self):self.exercise('sdk-with-joined-country')
    def test_legacy_branch_stays_explicitly_empty(self):self.exercise('sdk-without-nid-info')
    def test_partial_metadata_has_only_current_proven_fields(self):self.exercise('sdk-with-partial-metadata')
    def test_current_partial_metadata_uses_persistent_tid_provider(self):self.exercise('sdk-with-partial-metadata',release=True)
    def test_custom_device_metadata_preserves_fresh_network_and_auth_fields(self):
        from vampir_core.bot_device_settings import connection_presets
        self.exercise('sdk-with-partial-metadata',release=True,device_settings=connection_presets()[1]['device_settings'])
    def test_conflicting_missing_or_noncanonical_country_never_connects(self):
        for country in ('UA',None,'hk',''):
            with self.subTest(country=country):self.exercise('sdk-with-joined-country',sdk_country=country)


if __name__=='__main__':unittest.main()
