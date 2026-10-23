"""Creation callback crosses every wrapper; auth/socket dependencies are fixtures."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch


class CreationWrapperTests(unittest.TestCase):
    def tool(self):
        path = Path(__file__).parent / 'vampir-headless/probe-selected-game-login.py'
        spec = importlib.util.spec_from_file_location('creation_wrapper_test', path)
        tool = importlib.util.module_from_spec(spec)
        import sys
        sys.modules[spec.name] = tool
        spec.loader.exec_module(tool)
        return tool

    def test_run_to_selected_lobby_callback_preserves_factory(self):
        tool = self.tool(); factory = MagicMock()
        source, lobby = MagicMock(), MagicMock()
        def module(name, filename):
            if filename == 'game-source-profile.py': return source
            if filename == 'probe-lobby-sdk-login.py': return lobby
            self.fail('Unexpected auth or network module')
        def exchange(*args, **kwargs):
            kwargs['_use_session'](SimpleNamespace(summary={}))
            return SimpleNamespace(summary={})
        lobby.run.side_effect = exchange
        with patch.object(tool, 'module', side_effect=module), patch.object(tool, '_after_lobby', return_value={'fixture': True}) as after:
            result = tool.run('fixture@unit.invalid', selected_profile='recovered-release',
                manifest_path=Path('fixture.json'), socks_port=None, server_policy_byte=0,
                extra_number=1, context='windows-sdk-initial-reset', region='EU', server_id=381,
                read_character_list=True, creation_factory=factory)
        self.assertEqual(result, {'fixture': True})
        self.assertIs(after.call_args.kwargs['creation_factory'], factory)
        factory.assert_not_called()

    def test_after_lobby_to_game_exchange_preserves_factory(self):
        tool = self.tool(); factory = MagicMock(); sock = MagicMock()
        target = SimpleNamespace(host='unit.invalid', port=1234, server_id=381, group_id=1)
        source = SimpleNamespace(source_exe_sha256='fixture-sha', app_version='fixture', compiled_tag='fixture')
        context = SimpleNamespace(sdk_data=SimpleNamespace(joined_country_code='UA'),
            binding=SimpleNamespace(nm_device_key='fixture'), netmarble_id='fixture', nid_metadata='')
        lobby = SimpleNamespace(summary=dict(login_server_id=381, login_after_server_selection=True,
            lobby_open_during_game=True, login_result_code=0), server_list_response=SimpleNamespace(groups=(), servers=()), response=object())
        target_module = SimpleNamespace(choose_target=lambda *args, **kwargs: target)
        system_module = SimpleNamespace(observe_inputs=lambda: ('fixture-cpu', 'fixture-os'))
        version_module = SimpleNamespace(prepare_version=lambda **kwargs: object())
        def module(name, filename):
            return {'probe-selected-game-version.py': target_module, 'windows-system-inputs.py': system_module,
                'probe-game-version.py': version_module}[filename]
        with patch.object(tool, 'module', side_effect=module), patch.object(tool, 'connect_direct', return_value=sock), \
             patch.object(tool, 'direct_game_address_context', return_value=SimpleNamespace(address='192.0.2.1', source='fixture')), \
             patch.object(tool, 'prepare_initial_windows_game_login', return_value=SimpleNamespace(raw_bytes=(0, 0, 1))), \
             patch.object(tool, 'exchange_game_login', return_value={'fixture': True}) as exchange:
            result = tool._after_lobby(lobby, auth={'context': context}, selection_proof={'target': target},
                source=source, socks_port=None, extra_number=1, context='windows-sdk-initial-reset', region='EU',
                server_id=381, selection=None, server_list_only=False, state={}, phase=lambda value: None,
                read_character_list=True, creation_factory=factory)
        self.assertEqual(result['game'], {'fixture': True})
        self.assertIs(exchange.call_args.kwargs['creation_factory'], factory)
        sock.close.assert_called_once(); factory.assert_not_called()


if __name__ == '__main__': unittest.main()
