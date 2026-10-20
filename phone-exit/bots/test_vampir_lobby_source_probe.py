import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
SNAPSHOT = ROOT / 'public-cdn-snapshots/4939dc4752684068106f52bc4954d3f8ebd43ff470fa43d1ae14e8f0d0a6736a/manifest.json'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / 'vampir-headless' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class LobbySourceProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.tool = load('lobby_probe_test', 'probe-lobby-connection.py')

    def snapshot(self, root, *, address=None, port=None):
        manifest = json.loads(SNAPSHOT.read_text('utf-8'))
        body = (SNAPSHOT.parent / 'body.bin').read_bytes()
        if address is not None or port is not None:
            document = self.tool.decode_cdn_config_document(body)
            selected = next(entry for entry in document['server_list'] if entry.get('type') == 'REAL')
            if address is not None: selected['detail']['lobbyAddress'] = address
            if port is not None: selected['detail']['lobbyPort'] = port
            body = json.dumps(document).encode()
            manifest['body_sha256'] = hashlib.sha256(body).hexdigest()
        data = json.dumps(manifest).encode()
        folder = Path(root) / hashlib.sha256(data).hexdigest()
        folder.mkdir()
        path = folder / 'manifest.json'
        path.write_bytes(data); (folder / 'body.bin').write_bytes(body)
        return path

    def test_real_snapshot_route_and_public_endpoint_validation(self):
        endpoint = self.tool.selected_endpoint(SNAPSHOT, route=self.tool.SocksRoute(17948))
        self.assertEqual(endpoint[1], 12000)
        with self.assertRaises(ValueError): self.tool.selected_endpoint(SNAPSHOT, route=self.tool.SocksRoute(17949))
        for address, port in (('127.0.0.1', None), ('192.168.1.1', None), ('::1', None),
                (None, '0'), (None, '65536'), (None, '12000x')):
            with tempfile.TemporaryDirectory() as temp:
                path = self.snapshot(temp, address=address, port=port)
                with self.assertRaises(ValueError): self.tool.selected_endpoint(path, route=self.tool.SocksRoute(17948))

    def test_one_connection_reads_bounded_data_and_always_closes_without_sends(self):
        for outcome in (socket.timeout(), b'', b'fixture bytes', ConnectionResetError()):
            connection = Mock()
            if isinstance(outcome, Exception): connection.recv.side_effect = outcome
            else: connection.recv.return_value = outcome
            with patch.object(self.tool.SocksRoute, 'connect', return_value=connection) as connect:
                result = self.tool.probe(SNAPSHOT, socks_port=17948)
            self.assertTrue(result['tcp_connected'])
            self.assertEqual(result['client_game_packets_sent'], 0)
            connection.recv.assert_called_once_with(65536)
            connection.send.assert_not_called(); connection.sendall.assert_not_called()
            connection.close.assert_called_once()
            self.assertEqual(connect.call_args.kwargs['timeout'], 10)

    def test_tampered_body_is_rejected_before_connect(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.snapshot(temp)
            (path.parent / 'body.bin').write_bytes(b'changed')
            with patch.object(self.tool.SocksRoute, 'connect') as connect:
                with self.assertRaises(ValueError): self.tool.probe(path, socks_port=17948)
                connect.assert_not_called()


class BaseGameProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.tool = load('base_game_profile_test', 'game-source-profile.py')

    def test_actual_sources_are_verified_and_profile_is_explicit(self):
        profile = self.tool.load_profile(selected_profile='recovered-base')
        self.assertEqual(profile.app_version, '1.12.14')
        self.assertEqual(profile.config_prefix, 'real')
        self.assertFalse(profile.active_game_cache_verified)
        with self.assertRaises(ValueError): self.tool.load_profile(selected_profile='automatic')

    def test_changed_ini_fails_before_its_values_are_used(self):
        original = ROOT / 'resource-config-snapshots' / self.tool.SNAPSHOT
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / 'resource-config-snapshots' / self.tool.SNAPSHOT
            folder.mkdir(parents=True)
            (folder / 'manifest.json').write_bytes((original / 'manifest.json').read_bytes())
            (folder / 'DefaultGame.ini').write_bytes(b'changed')
            with self.assertRaises(ValueError): self.tool.load_profile(selected_profile='recovered-base', root=temp)


if __name__ == '__main__': unittest.main()
