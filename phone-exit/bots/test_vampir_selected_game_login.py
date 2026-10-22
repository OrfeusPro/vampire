import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import unittest

import test_vampir_initial_game_login as input_tests


class SelectedGameLoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'vampir-headless/probe-selected-game-login.py'
        spec = importlib.util.spec_from_file_location('test_selected_game_login', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)

    def kwargs(self):
        return dict(selected_profile='recovered-base', manifest_path=Path('fixture'), socks_port=17948,
            server_policy_byte=0, extra_number=123, context='windows-sdk-initial-reset', region='JP', server_id=42)

    def test_auth_stays_in_memory_and_same_lobby_result_supplies_login(self):
        self.check_auth_and_clock('')

    def test_current_source_uses_fresh_lobby_clock(self):
        self.check_auth_and_clock(self.tool.PING_CLOCK_SOURCE_SHA256)

    def test_direct_route_reaches_game_with_socket_address_and_no_socks(self):
        self.check_auth_and_clock(self.tool.PING_CLOCK_SOURCE_SHA256, direct=True)

    def test_explicit_world_start_propagates_current_source_and_permission(self):
        self.check_auth_and_clock(self.tool.PING_CLOCK_SOURCE_SHA256, world_start=True)

    def test_explicit_world_finish_propagates_permission(self):
        self.check_auth_and_clock(self.tool.PING_CLOCK_SOURCE_SHA256,world_start=True,world_finish=True)

    def test_world_observation_permission_propagates(self):
        self.check_auth_and_clock(self.tool.PING_CLOCK_SOURCE_SHA256,world_start=True,world_finish=True,observation=20)

    def check_auth_and_clock(self, source_sha, world_start=False,world_finish=False,observation=0,direct=False):
        from vampir_core.lobby_packets import LobbyVersionResultBody
        version, inputs = input_tests.InitialGameLoginTests().inputs()
        def lobby(email, **kwargs):
            self.assertEqual(kwargs['socks_port'], None if direct else 17948)
            self.assertEqual(kwargs['auth_flow'], 'launcher')
            self.assertEqual(kwargs['context'], 'sdk-with-partial-metadata')
            kwargs['_consume_auth'](**{name: inputs[name] for name in ('binding', 'sdk_data', 'netmarble_id')},
                nid_metadata='{"I_PID":"current-player-fixture"}')
            record = SimpleNamespace(u32=(7, 42, 0, 0), enums=(0, 1, 0), flags=(False,) * 5,
                array50=('private-list-identity-fixture',), strings=('private-record-text',))
            group = SimpleNamespace(raw_08=7, raw_20=4)
            data = SimpleNamespace(servers=(record,), groups=(group,))
            selected_id = kwargs['_select_server'](data, inputs['sdk_data'].joined_country_code)
            result = SimpleNamespace(response=inputs['lobby_result'],
                version_response=LobbyVersionResultBody(0, False, (123, 456), 540),
                server_list_response=data,
                summary={'login_result_code': 0, 'login_after_server_selection': True, 'login_server_id': selected_id,
                         'lobby_open_during_game': True})
            kwargs['_use_session'](result)
            return result
        prepare = Mock(return_value=version)
        target_module = SimpleNamespace(choose_target=lambda *args, **kwargs:
                SimpleNamespace(server_id=42, group_id=7, host='game.example.com', port=12001))
        modules = [SimpleNamespace(load_profile=lambda **kwargs: SimpleNamespace(app_version='1.12.14', compiled_tag=version.strings[9], source_exe_sha256=source_sha)),
            SimpleNamespace(run=lobby), target_module, target_module,
            SimpleNamespace(observe_inputs=lambda: ('cpu', 'windows')),
            SimpleNamespace(prepare_version=prepare)]
        connection = Mock()
        connection.getsockname.return_value = ('127.0.0.1', 1234)
        connection.get_proxy_sockname.return_value = ('0.0.0.0', 0)
        connection.getsockname.return_value = ('192.168.1.25', 49152)
        with patch.object(self.tool, 'module', side_effect=modules), patch.object(self.tool, 'SocksRoute') as route, \
                patch.object(self.tool, 'connect_direct', return_value=connection) as direct_connect, \
                patch.object(self.tool, 'exchange_game_login', return_value={'login_result_code': 0}) as exchange:
            route.return_value.connect.return_value = connection
            options = self.kwargs()
            if direct: options['socks_port'] = None
            if world_start: options['selected_profile'] = 'recovered-release'
            result = self.tool.run('fixture@example.invalid', auth_flow='launcher', language_code=1,
                lobby_context='sdk-with-partial-metadata', read_character_list=True, character_index=0,
                read_world_start=world_start, read_world_finish=world_finish, observe_world_seconds=observation, **options)
        packet = exchange.call_args.args[2]
        clock = exchange.call_args.kwargs['ping_clock']
        if source_sha:
            self.assertEqual(clock.offset_minutes, 540)
        else:
            self.assertIsNone(clock)
        if direct:
            self.assertEqual(prepare.call_args.kwargs['local_address'], '192.168.1.25')
            self.assertEqual(result['game_address_source'], 'direct_socket_ipv4')
            connection.get_proxy_sockname.assert_not_called()
            direct_connect.assert_called_once_with('game.example.com', 12001, timeout=10)
            route.assert_not_called()
        else:
            self.assertIsNone(prepare.call_args.kwargs['local_address'])
            connection.getsockname.assert_not_called()
            self.assertEqual(result['game_address_source'], 'socks_bound_unavailable')
            direct_connect.assert_not_called()
        self.assertEqual(packet.strings[8], 'sdk-token-fixture')
        self.assertEqual(packet.strings[:2], ('lobby-first-fixture', 'lobby-second-fixture'))
        self.assertEqual(packet.integers[:2], (123, 42))
        self.assertEqual(packet.raw_bytes, (3,3,1,0,0))
        self.assertTrue(exchange.call_args.kwargs['read_character_list'])
        self.assertEqual(exchange.call_args.kwargs['character_index'],0)
        self.assertEqual(exchange.call_args.kwargs['read_world_start'],world_start)
        self.assertEqual(exchange.call_args.kwargs['read_world_finish'],world_finish)
        self.assertEqual(exchange.call_args.kwargs['observe_world_seconds'],observation)
        self.assertEqual(exchange.call_args.kwargs['source_sha256'],source_sha)
        self.assertEqual(packet.strings[11],'{"I_PID":"current-player-fixture"}')
        self.assertEqual(result['login_language_code'],1)
        connection.close.assert_called_once()
        self.assertNotIn('sdk-token-fixture', str(result))
        self.assertNotIn('current-player-fixture',str(result))
        self.assertNotIn('nm-fixture', str(result))
        self.assertNotIn('private-list-identity-fixture', str(result))
        self.assertNotIn('private-record-text', str(result))
        self.assertEqual(result['region_server_states'], [dict(server_id=42, enums=(0, 1, 0),
            flags=(False,) * 5, array50_count=1, excluded_by_native_state=False, sdk_joined_country_allowed=None)])
        self.assertEqual(result['game']['login_result_code'], 0)
        self.assertEqual(result['sdk_auth_flow'], 'launcher')
        self.assertEqual(repr(self.tool.AuthForGame(**{k: inputs[k] for k in ('binding', 'sdk_data', 'netmarble_id')})), 'AuthForGame()')

    def test_missing_auth_does_not_connect_to_game(self):
        modules = [SimpleNamespace(load_profile=lambda **kwargs: SimpleNamespace(app_version='fixture')),
            SimpleNamespace(run=lambda *args, **kwargs: SimpleNamespace(summary={}, server_list_response=object()))]
        with patch.object(self.tool, 'module', side_effect=modules), patch.object(self.tool, 'SocksRoute') as route:
            result = self.tool.run('fixture@example.invalid', **self.kwargs())
        route.assert_not_called()
        self.assertEqual(result['status'], 'selected_lobby_context_not_received')

    def test_wrong_or_closed_lobby_context_never_opens_game_connection(self):
        _, inputs = input_tests.InitialGameLoginTests().inputs()
        target = SimpleNamespace(server_id=42, group_id=7, host='game.example.com', port=12001)
        record = SimpleNamespace(u32=(7, 42, 0, 0), enums=(0, 1, 0), flags=(False,) * 5, array50=())
        data = SimpleNamespace(servers=(record,), groups=(SimpleNamespace(raw_08=7, raw_20=4),))
        base = dict(login_result_code=0, login_after_server_selection=True, login_server_id=42, lobby_open_during_game=True)
        for changed in ({'login_server_id': 0}, {'login_server_id': 43}, {'login_after_server_selection': False},
                        {'lobby_open_during_game': False}, {'login_result_code': 16}):
            with self.subTest(changed=changed), patch.object(self.tool, 'module', return_value=SimpleNamespace(
                    choose_target=lambda *args, **kwargs: target)), patch.object(self.tool, 'SocksRoute') as route:
                with self.assertRaises(ValueError):
                    self.tool._after_lobby(SimpleNamespace(summary=dict(base, **changed), server_list_response=data),
                        auth={'context': self.tool.AuthForGame(**{k: inputs[k] for k in ('binding', 'sdk_data', 'netmarble_id')})},
                        selection_proof={'target': target}, source=SimpleNamespace(app_version='fixture'), socks_port=17948,
                        extra_number=0, context='windows-sdk-initial-reset', region='JP', server_id=42,
                        selection=None, server_list_only=False, state={}, phase=lambda value: None)
                route.assert_not_called()

    def test_policy_validation_happens_before_auth_and_error_text_is_hidden(self):
        with patch.object(self.tool, 'module') as load:
            for changed in ({'extra_number': -1}, {'context': ''}, {'server_id': 0}, {'region': 'unknown'},
                    {'language_code':True},{'language_code':256},{'character_index':0},{'read_character_list':True,'character_index':True},{'read_character_list':True,'character_index':-1}):
                with self.assertRaises(ValueError): self.tool.run('fixture@example.invalid', **dict(self.kwargs(), **changed))
            load.assert_not_called()
        with patch.object(self.tool, 'module', side_effect=RuntimeError('secret-auth-context')):
            result = self.tool.run('fixture@example.invalid', **self.kwargs())
        self.assertEqual(result['stage'], 'source_validation')
        self.assertNotIn('secret-auth-context', str(result))


if __name__ == '__main__': unittest.main()
