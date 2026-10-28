"""Prepared runtime routing on synthetic admission; no external IO or login.

Bundle provenance validation has its own source-bound suite. These tests mock
only that boundary to exercise exact-source policy, immutable routing and scope.
"""
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core import runtime_admission as admission
from vampir_core import release_bundle
from vampir_core.gmc2_context import Gmc2Geo,decode_gmc2_geo,VERIFIED_SOURCE_SHA256,SdkInputs
from vampir_core.session_clock import LobbyPingClock,INITIAL_PING_SOURCES
from vampir_core.heartbeat import PeriodicPing,HEARTBEAT_SOURCES
from vampir_core.world_move_start import WORLD_PROBE_SOURCES
from vampir_core.lobby_packets import decode_lobby_version_result

WORKSPACE=HERE.parents[1]
TARGET='a'*64
SELECTOR='prepared:'+'b'*64


def load(name):
    spec=importlib.util.spec_from_file_location('prepared_test_'+name.replace('-','_'),HERE/'vampir-headless'/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def bundle():
    return dict(source_sha256=TARGET,selected_profile=SELECTOR,runtime_adapter=admission.descriptor(WORKSPACE),
        bundle_sha256='b'*64,game_profile={},sdk_profile={})


class PreparedRuntimeTests(unittest.TestCase):
    def scope(self):
        return admission.profile_scope('prepared-next',root=Path('fixture'),workspace=WORKSPACE)

    def test_no_source_bypass_outside_scope_and_no_global_set_expansion(self):
        sets=(VERIFIED_SOURCE_SHA256,INITIAL_PING_SOURCES,HEARTBEAT_SOURCES,WORLD_PROBE_SOURCES)
        self.assertTrue(all(TARGET not in values for values in sets))
        self.assertFalse(admission.permits(TARGET,'game-login-world-v1'))
        with self.assertRaises(ValueError):decode_gmc2_geo(b'{}',source_sha256=TARGET)
        reply=decode_lobby_version_result(struct.pack('<IBQQH',0,0,123,456,540))
        with self.assertRaises(ValueError):LobbyPingClock.from_version_result(reply,source_sha256=TARGET)
        with patch.object(release_bundle,'validate',return_value=bundle()):
            with self.scope() as selected:
                self.assertEqual(selected,SELECTOR)
                self.assertTrue(admission.permits(TARGET,'game-login-world-v1'))
                self.assertFalse(admission.permits('c'*64,'game-login-world-v1'))
                self.assertFalse(admission.permits(TARGET,'quests'))
                clock=LobbyPingClock.from_version_result(reply,source_sha256=TARGET)
                ping=clock.initial_ping(utc_millis=1792600142863)
                heartbeat=PeriodicPing(clock,ping,source_sha256=TARGET)
                self.assertEqual(heartbeat.queued_count,1)
            self.assertFalse(admission.permits(TARGET,'game-login-world-v1'))
        self.assertTrue(all(TARGET not in values for values in sets))

    def test_named_geo_policy_and_launcher_restriction_keep_actual_source(self):
        body=json.dumps(dict(errorCode=0,resultData=dict(geoIp=dict(clientIp='8.8.8.8',geoLocation='a1',isoCountry='JP')))).encode()
        with patch.object(release_bundle,'validate',return_value=bundle()):
            with self.scope():
                geo=decode_gmc2_geo(body,source_sha256=TARGET)
                self.assertEqual(geo.source_sha256,TARGET)
                self.assertEqual(geo.metadata(previous_country='HK')['I_CountryCD'],'HK')
                context=SdkInputs('fixture@example.invalid',None,{}, {},SELECTOR,None,TARGET,geo,0)
                context.check_auth_operation(auth_flow='launcher')
                with self.assertRaises(ValueError):context.check_auth_operation(auth_flow='nid')
                with self.assertRaises(ValueError):context.check_auth_operation(auth_flow='launcher',create_sdk_player=True)

    def test_scope_restores_on_exception_and_threads_are_explicitly_bound(self):
        with patch.object(release_bundle,'validate',return_value=bundle()):
            with self.scope():
                with ThreadPoolExecutor(max_workers=1) as pool:
                    self.assertFalse(pool.submit(lambda:admission.permits(TARGET,'periodic-ping-v1')).result())
                    worker=admission.bind_worker(lambda:admission.permits(TARGET,'periodic-ping-v1'))
                    self.assertTrue(pool.submit(worker).result())
                    self.assertFalse(pool.submit(lambda:admission.permits(TARGET,'periodic-ping-v1')).result())
                with self.assertRaisesRegex(RuntimeError,'fixture'):
                    with self.scope():raise RuntimeError('fixture')
                self.assertTrue(admission.permits(TARGET,'periodic-ping-v1'))
        self.assertFalse(admission.permits(TARGET,'periodic-ping-v1'))

    def test_nested_flow_never_rereads_next_pointer_or_changes_bundle(self):
        with patch.object(release_bundle,'validate',return_value=bundle()) as validate:
            with self.scope():
                with self.scope() as selected:self.assertEqual(selected,SELECTOR)
                self.assertEqual(validate.call_count,1)
                with self.assertRaises(ValueError):
                    with admission.profile_scope('prepared:'+'c'*64,root='fixture',workspace=WORKSPACE):pass
                value=admission.current_bundle(SELECTOR);value['source_sha256']='0'*64
                self.assertEqual(admission.current_bundle(SELECTOR)['source_sha256'],TARGET)
        self.assertIsNone(admission.current_bundle(SELECTOR))

    def test_missing_or_altered_adapter_rejected_before_body(self):
        for adapter in (None,dict(id=admission.ADAPTER_ID),{**admission.descriptor(WORKSPACE),'policies':['quests']}):
            value=bundle();value['runtime_adapter']=adapter
            with patch.object(release_bundle,'validate',return_value=value):
                with self.assertRaisesRegex(ValueError,'runtime adapter'):
                    with self.scope():raise AssertionError('Body must not run')

    def test_selected_probe_passes_pinned_profile_without_historical_sdk_fallback(self):
        tool=load('probe-selected-game-login')
        lobby=Mock(return_value=SimpleNamespace(summary={},server_list_response=object()))
        source=SimpleNamespace(source_exe_sha256=TARGET,live_probe_only=True,bounded_world_probe=True)
        def module(name,filename):
            if filename=='game-source-profile.py':return SimpleNamespace(load_profile=lambda **_:source)
            if filename=='probe-lobby-sdk-login.py':return SimpleNamespace(run=lobby)
            raise AssertionError(filename)
        arguments=dict(selected_profile='prepared-next',manifest_path=Path('fixture'),socks_port=17948,
            server_policy_byte=0,extra_number=0,context='windows-sdk-initial-reset',region='JP',server_id=42,
            read_character_list=True,character_index=0,read_world_start=True,read_world_finish=True,
            observe_world_seconds=20,auth_flow='launcher')
        with patch.object(release_bundle,'validate',return_value=bundle()),patch.object(tool,'module',side_effect=module):
            result=tool.run('fixture@example.invalid',**arguments)
            self.assertEqual(result['status'],'selected_lobby_context_not_received')
            self.assertEqual(lobby.call_args.kwargs['selected_profile'],SELECTOR)
            lobby.reset_mock()
            result=tool.run('fixture@example.invalid',**{**arguments,'read_quest_list':True})
            self.assertEqual(result['stage'],'source_validation');lobby.assert_not_called()

    def test_lobby_routes_prepared_sdk_to_same_immutable_bundle(self):
        tool=load('probe-lobby-sdk-login')
        class BoundaryReached(RuntimeError):pass
        sdk=SimpleNamespace(load_inputs=Mock(side_effect=BoundaryReached))
        source=SimpleNamespace(source_exe_sha256=TARGET,source_snapshot_sha256='c'*64,live_probe_only=True)
        def module(name,filename):
            if filename=='game-source-profile.py':return SimpleNamespace(load_profile=lambda **_:source)
            if filename=='probe-lobby-connection.py':return SimpleNamespace(selected_endpoint=lambda *_,**__:('fixture.invalid',12000))
            if filename=='run-nid-sdk-sign-in.py':return sdk
            raise AssertionError(filename)
        with patch.object(release_bundle,'validate',return_value=bundle()),patch.object(tool,'module',side_effect=module):
            with self.assertRaises(BoundaryReached):tool.run('fixture@example.invalid',selected_profile='prepared-next',
                manifest_path=Path('fixture'),socks_port=17948,context='sdk-without-nid-info',auth_flow='launcher')
            self.assertEqual(sdk.load_inputs.call_args.kwargs['selected_profile'],SELECTOR)

    def test_multiple_workers_share_one_pinned_bundle_not_next_pointer(self):
        tool=load('run-live-sessions');observed=[]
        accounts=[dict(bot_id='fixture'+str(i),email='fixture'+str(i)+'@example.invalid',socks_port=17948,
            region='JP',server_id=42,character_index=0) for i in range(2)]
        def run(email,**kwargs):
            observed.append((kwargs['selected_profile'],admission.permits(TARGET,'game-login-world-v1')))
            return dict(status='fixture',game=dict(status='fixture'))
        # Real loopback server lifecycle; the probe is a local callable, never an
        # external transport or authentication. Port 0 requests an OS free port.
        with patch.object(release_bundle,'validate',return_value=bundle()) as validate,\
                patch.object(tool,'verify_launch_source',return_value=dict(profile=SELECTOR)):
            result=tool.run_accounts(accounts,{'fixture0':'fixture','fixture1':'fixture'},manifest=Path('fixture'),
                client_version=1,profile='prepared-next',probe=SimpleNamespace(run=run),port=0,max_runtime_seconds=1)
        self.assertEqual(len(result),2);self.assertEqual(observed,[(SELECTOR,True)]*2)
        self.assertEqual(validate.call_count,1)
        self.assertFalse(admission.permits(TARGET,'game-login-world-v1'))

    def test_local_world_path_uses_actual_source_with_same_framing_and_heartbeat(self):
        import test_vampir_game_login_probe as protocol
        from test_vampir_world_entry_flow import reserve_body,finish_body
        fixture=protocol.GameLoginProbeTests()
        with patch.object(release_bundle,'validate',return_value=bundle()),patch.object(protocol,'SOURCE_SHA256',TARGET):
            with self.scope():
                result,captures=fixture.world_attempt(world_reserve_body=reserve_body(),
                    world_start_body=struct.pack('<IIIIIBBQ',0,9,2,3,4,0,0,77),
                    read_world_finish=True,world_finish_body=finish_body(),
                    ping_clock=LobbyPingClock(540),observe_world_seconds=.05,advance_clock=True)
        self.assertEqual(captures,[(1,0),(16,1),(3,2),(101,3),(109,4),(203,5),(205,6),(16,7)])
        self.assertEqual(result['status'],'world_observation_complete')
        self.assertEqual(result['periodic_ping_queued'],1)
        self.assertEqual(result['ping_results_received'],2)
        self.assertFalse(result['game_session_ready'])

    def test_nid_loader_uses_prepared_nid_and_public_profiles_without_fallback(self):
        tool=load('run-nid-sdk-sign-in')
        class BoundaryReached(RuntimeError):pass
        with tempfile.TemporaryDirectory() as temporary:
            exe=Path(temporary)/'fixture.exe';exe.write_bytes(b'fixture executable')
            target=hashlib.sha256(exe.read_bytes()).hexdigest()
            value=bundle();value['source_sha256']=target
            source=dict(source=str(exe),source_sha256=target,profile_sha256='b'*64,profile={})
            public=dict(source,request={})
            loader=SimpleNamespace(load_prepared_profile=Mock(side_effect=lambda kind,**_:
                source if kind=='nid' else public),load_release_profile=Mock(side_effect=AssertionError('Historical SDK fallback')))
            spec=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module:None))
            binding=SimpleNamespace(kind='real',identity_recorded=True,nid_identity_recorded=True,
                confirmation='observed',device_key='fixture-device',nid_device_key='fixture-nid',nm_device_key='fixture-nm')
            with patch.object(release_bundle,'validate',return_value=value),\
                    patch.object(tool.importlib.util,'spec_from_file_location',return_value=spec),\
                    patch.object(tool.importlib.util,'module_from_spec',return_value=loader),\
                    patch.object(tool,'DeviceRegistry',return_value=SimpleNamespace(get=lambda _:binding)),\
                    patch.object(tool,'observe_windows_device_identity',return_value=binding),\
                    patch.object(tool,'fetch_gmc2',side_effect=BoundaryReached):
                with self.assertRaises(BoundaryReached):tool.load_inputs('fixture@example.invalid',selected_profile='prepared-next')
            self.assertEqual([call.args[0] for call in loader.load_prepared_profile.call_args_list],['nid','public_gmc2'])
            self.assertTrue(all(call.kwargs['selected_profile']==SELECTOR for call in loader.load_prepared_profile.call_args_list))
            loader.load_release_profile.assert_not_called()

    def test_prepared_direct_sdk_operations_refuse_before_input_or_network(self):
        tool=load('run-nid-sdk-sign-in')
        with patch.object(release_bundle,'validate',return_value=bundle()),patch.object(tool,'load_inputs') as inputs:
            for changes in (dict(auth_flow='nid'),dict(auth_flow='launcher',create_sdk_player=True),
                    dict(auth_flow='launcher',fetch_player=True),dict(auth_flow='launcher',first_sdk_login=True)):
                with self.assertRaises(ValueError):tool.run('fixture@example.invalid',selected_profile='prepared-next',**changes)
            inputs.assert_not_called()


if __name__=='__main__':unittest.main()
