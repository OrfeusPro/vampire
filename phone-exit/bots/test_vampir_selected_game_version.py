import importlib.util
from pathlib import Path
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock, patch

from test_vampir_game_server_target import record, listing

HERE = Path(__file__).parent


class SelectedGameVersionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('test_selected_game_version', HERE / 'vampir-headless/probe-selected-game-version.py')
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)

    def test_explicit_id_or_lowest_valid_unique_id_without_order_dependency(self):
        data = listing(record(207), record(1, host='127.0.0.1'), record(42))
        self.assertEqual(self.tool.choose_target(data, selection='lowest-valid-id').server_id, 42)
        self.assertEqual(self.tool.choose_target(replace(data, servers=tuple(reversed(data.servers))), selection='lowest-valid-id').server_id, 42)
        self.assertEqual(self.tool.choose_target(data, server_id=207).server_id, 207)
        data = listing(record(42), record(42), record(207))
        self.assertEqual(self.tool.choose_target(data, selection='lowest-valid-id').server_id, 207)

    def test_invalid_policy_and_alternate_branch_fail_before_game_io(self):
        for kwargs in ({}, {'server_id':42, 'selection':'lowest-valid-id'}, {'selection':'first'}):
            with self.assertRaises(ValueError): self.tool.choose_target(listing(), **kwargs)
        with self.assertRaises(ValueError): self.tool.choose_target(listing(record(host='127.0.0.1')), selection='lowest-valid-id')
        with self.assertRaises(ValueError):
            self.tool.choose_target(replace(listing(), flags=(False, True)), selection='lowest-valid-id')
        with self.assertRaises(ValueError):
            self.tool.run('fixture@example.invalid', selected_profile='recovered-base',
                manifest_path=Path('missing'), socks_port=17948, server_policy_byte=0, selection='unsupported')

    def test_auth_failure_reports_phase_without_exception_contents(self):
        def fail(**kwargs):
            kwargs['_progress']('nid_browser')
            raise RuntimeError('secret-token-and-auth-url')
        source = SimpleNamespace(load_profile=lambda **kwargs: SimpleNamespace(app_version='fixture'))
        lobby = SimpleNamespace(run=lambda email, **kwargs: fail(**kwargs))
        with patch.object(self.tool, 'module', side_effect=[source, lobby]), patch.object(self.tool, 'SocksRoute') as route:
            result = self.tool.run('fixture@example.invalid', selected_profile='recovered-base',
                manifest_path=Path('fixture'), socks_port=17948, server_policy_byte=0, server_id=42)
        self.assertEqual(result, dict(status='selected_game_version_not_completed',
            stage='nid_browser', game_login_sent=False, error_type='RuntimeError'))
        route.assert_not_called()

    def test_fresh_list_target_and_socket_close_on_game_protocol_error(self):
        source = SimpleNamespace(load_profile=lambda **kwargs: SimpleNamespace(app_version='fixture'))
        lobby = SimpleNamespace(run=lambda email, **kwargs: SimpleNamespace(
            summary={'server_list_result_code': 0}, server_list_response=listing(record(42))))
        system = SimpleNamespace(observe_inputs=lambda: ('cpu-fixture', 'windows-fixture'))
        prepare = Mock(return_value='payload-fixture')
        payload = SimpleNamespace(prepare_version=prepare)
        connection = Mock()
        connection.getsockname.return_value = ('127.0.0.1', 1234)
        connection.get_proxy_sockname.return_value = ('0.0.0.0', 0)
        with patch.object(self.tool, 'module', side_effect=[source, lobby, system, payload]), \
                patch.object(self.tool, 'DeviceRegistry') as registry, \
                patch.object(self.tool, 'SocksRoute') as route, \
                patch.object(self.tool, 'exchange_version', side_effect=ValueError('private-server-data')):
            registry.return_value.get.return_value = SimpleNamespace(nm_device_key='secret-device-key')
            route.return_value.connect.return_value = connection
            result = self.tool.run('fixture@example.invalid', selected_profile='recovered-base',
                manifest_path=Path('fixture'), socks_port=17948, server_policy_byte=0, server_id=42)
        route.return_value.connect.assert_called_once_with('game.example.com', 12001, timeout=10)
        connection.close.assert_called_once()
        self.assertIsNone(prepare.call_args.kwargs['local_address'])
        connection.getsockname.assert_not_called()
        self.assertEqual(result['stage'], 'game_version_exchange')
        self.assertEqual(result['selected_server_id'], 42)
        self.assertEqual(result['lobby'], {'server_list_result_code': 0})
        self.assertNotIn('private-server-data', str(result))
        self.assertNotIn('secret-device-key', str(result))


if __name__ == '__main__': unittest.main()
