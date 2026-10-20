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
        version, inputs = input_tests.InitialGameLoginTests().inputs()
        def lobby(email, **kwargs):
            kwargs['_consume_auth'](**{name: inputs[name] for name in ('binding', 'sdk_data', 'netmarble_id')})
            record = SimpleNamespace(u32=(7, 42, 0, 0), enums=(0, 1, 0), flags=(False,) * 5,
                array50=('private-list-identity-fixture',), strings=('private-record-text',))
            group = SimpleNamespace(raw_08=7, raw_20=4)
            return SimpleNamespace(response=inputs['lobby_result'],
                server_list_response=SimpleNamespace(servers=(record,), groups=(group,)),
                summary={'login_result_code': 0})
        prepare = Mock(return_value=version)
        modules = [SimpleNamespace(load_profile=lambda **kwargs: SimpleNamespace(app_version='1.12.14')),
            SimpleNamespace(run=lobby), SimpleNamespace(choose_target=lambda *args, **kwargs:
                SimpleNamespace(server_id=42, group_id=7, host='game.example.com', port=12001)),
            SimpleNamespace(observe_inputs=lambda: ('cpu', 'windows')),
            SimpleNamespace(prepare_version=prepare)]
        connection = Mock()
        connection.getsockname.return_value = ('127.0.0.1', 1234)
        connection.get_proxy_sockname.return_value = ('0.0.0.0', 0)
        with patch.object(self.tool, 'module', side_effect=modules), patch.object(self.tool, 'SocksRoute') as route, \
                patch.object(self.tool, 'exchange_game_login', return_value={'login_result_code': 0}) as exchange:
            route.return_value.connect.return_value = connection
            result = self.tool.run('fixture@example.invalid', **self.kwargs())
        packet = exchange.call_args.args[2]
        self.assertIsNone(prepare.call_args.kwargs['local_address'])
        connection.getsockname.assert_not_called()
        self.assertEqual(result['game_address_source'], 'socks_bound_unavailable')
        self.assertEqual(packet.strings[8], 'sdk-token-fixture')
        self.assertEqual(packet.strings[:2], ('lobby-first-fixture', 'lobby-second-fixture'))
        self.assertEqual(packet.integers[:2], (123, 42))
        connection.close.assert_called_once()
        self.assertNotIn('sdk-token-fixture', str(result))
        self.assertNotIn('nm-fixture', str(result))
        self.assertNotIn('private-list-identity-fixture', str(result))
        self.assertNotIn('private-record-text', str(result))
        self.assertEqual(result['region_server_states'], [dict(server_id=42, enums=(0, 1, 0),
            flags=(False,) * 5, array50_count=1, excluded_by_native_state=False, sdk_joined_country_allowed=None)])
        self.assertEqual(result['game']['login_result_code'], 0)
        self.assertEqual(repr(self.tool.AuthForGame(**{k: inputs[k] for k in ('binding', 'sdk_data', 'netmarble_id')})), 'AuthForGame()')

    def test_missing_auth_does_not_connect_to_game(self):
        modules = [SimpleNamespace(load_profile=lambda **kwargs: SimpleNamespace(app_version='fixture')),
            SimpleNamespace(run=lambda *args, **kwargs: SimpleNamespace(summary={}, server_list_response=object()))]
        with patch.object(self.tool, 'module', side_effect=modules), patch.object(self.tool, 'SocksRoute') as route:
            result = self.tool.run('fixture@example.invalid', **self.kwargs())
        route.assert_not_called()
        self.assertEqual(result['status'], 'lobby_context_not_received')

    def test_policy_validation_happens_before_auth_and_error_text_is_hidden(self):
        with patch.object(self.tool, 'module') as load:
            for changed in ({'extra_number': -1}, {'context': ''}, {'server_id': 0}, {'region': 'unknown'}):
                with self.assertRaises(ValueError): self.tool.run('fixture@example.invalid', **dict(self.kwargs(), **changed))
            load.assert_not_called()
        with patch.object(self.tool, 'module', side_effect=RuntimeError('secret-auth-context')):
            result = self.tool.run('fixture@example.invalid', **self.kwargs())
        self.assertEqual(result['stage'], 'source_validation')
        self.assertNotIn('secret-auth-context', str(result))


if __name__ == '__main__': unittest.main()
