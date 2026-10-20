import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
import unittest


class CaptureFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'vampir-headless/prepare-capture-filter.py'
        spec = importlib.util.spec_from_file_location('capture_filter_test_tool', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)

    def test_fresh_lobby_targets_are_saved_without_game_connection_or_auth_data(self):
        with TemporaryDirectory() as root:
            manifest = Path(root) / 'manifest.json';manifest.write_text('{}')
            output = Path(root) / 'filter.txt'
            def lobby(email, **kwargs):
                self.assertEqual(kwargs['auth_flow'], 'launcher')
                self.assertNotIn('_select_server', kwargs)
                kwargs['_consume_auth'](sdk_data=SimpleNamespace(joined_country_code='HK'),
                    private_token='secret-token-fixture', netmarble_id='secret-id-fixture')
                return SimpleNamespace(server_list_response=object(), summary={'login_result_code': 0})
            def choose(response, **kwargs):
                self.assertEqual(kwargs, dict(server_id=256, region='JP', joined_country_code='HK'))
                return SimpleNamespace(host='game.example', port=12001, server_id=256, group_id=253)
            modules = [SimpleNamespace(SOURCE_SHA='a'*64, load_profile=lambda **k: SimpleNamespace(app_version='fixture')),
                SimpleNamespace(selected_endpoint=lambda *a, **k: ('lobby.example', 12000)),
                SimpleNamespace(run=lobby), SimpleNamespace(choose_target=choose)]
            with patch.object(self.tool, 'module', side_effect=modules), patch.object(self.tool.SocksRoute, 'connect', side_effect=AssertionError('Game connect forbidden')):
                value = self.tool.run('fixture@example.invalid', manifest_path=manifest, socks_port=17948,
                    server_id=256, region='JP', output=output, password='private-password-fixture')
            self.assertEqual(output.read_text(), 'lobby.example:12000\ngame.example:12001\n')
            proof = json.loads(output.with_suffix('.txt.json').read_text())
            self.assertFalse(proof['game_login_sent']);self.assertFalse(proof['capture_started'])
            self.assertEqual(proof['server_id'], 256)
            for private in ('secret-token-fixture', 'secret-id-fixture', 'private-password-fixture', 'game.example'):
                self.assertNotIn(private, json.dumps(value) + json.dumps(proof))
            with patch.object(self.tool, 'module') as load:
                with self.assertRaises(ValueError):
                    self.tool.run('fixture@example.invalid', manifest_path=manifest, socks_port=17948,
                        server_id=256, region='JP', output=output)
                load.assert_not_called()

    def test_failed_lobby_does_not_write_filter(self):
        with TemporaryDirectory() as root:
            manifest = Path(root) / 'manifest.json'
            manifest.write_text('{}')
            output = Path(root) / 'filter.txt'
            modules = [SimpleNamespace(load_profile=lambda **k: object()),
                SimpleNamespace(selected_endpoint=lambda *a, **k: ('lobby.example', 12000)),
                SimpleNamespace(run=lambda *a, **k: SimpleNamespace(server_list_response=None, summary={}))]
            with patch.object(self.tool, 'module', side_effect=modules):
                with self.assertRaises(ValueError):
                    self.tool.run('fixture@example.invalid', manifest_path=manifest,
                        socks_port=17948, server_id=256, region='JP', output=output)
            self.assertFalse(output.exists())


if __name__ == '__main__': unittest.main()
