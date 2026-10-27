"""Current CDN -> lobby -> SDK boundary; no external connection or authentication."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
SNAPSHOT = Path('F:/PhoneExit Resources/Vampir/public-cdn-snapshots/eafe5898c1241b785138f4be8eede2b413ee2702dab8c30765beda41fb6cc12a/manifest.json')
CONFIG = 'f93042b23066af7a5a6dfedaa554f12dc88302e4a9f260da4ced0538db7f5251'
SOURCE = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / 'vampir-headless' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class LobbyCandidate11318Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.endpoint = load('lobby_endpoint_candidate_11318', 'probe-lobby-connection.py')
        cls.lobby = load('lobby_sdk_candidate_11318', 'probe-lobby-sdk-login.py')

    def endpoint_for(self, path=SNAPSHOT, port=1087, **kwargs):
        return self.endpoint.selected_endpoint(path, route=self.endpoint.SocksRoute(port),
            expected_config_snapshot_sha256=CONFIG, **kwargs)

    def mutated(self, root, *, profile=None, address=None):
        manifest = json.loads(SNAPSHOT.read_bytes())
        body = (SNAPSHOT.parent / 'body.bin').read_bytes()
        if profile:
            manifest['profile'].update(profile)
        if address:
            document = self.endpoint.decode_cdn_config_document(body)
            selected = next(row for row in document['server_list']
                if row['type'] == document['select_server']['type'])
            selected['detail']['lobbyAddress'] = address
            body = json.dumps(document).encode()
            manifest['body_sha256'] = hashlib.sha256(body).hexdigest()
        data = json.dumps(manifest).encode()
        folder = Path(root) / hashlib.sha256(data).hexdigest()
        folder.mkdir()
        (folder / 'manifest.json').write_bytes(data)
        (folder / 'body.bin').write_bytes(body)
        return folder / 'manifest.json'

    def test_actual_current_snapshot_reaches_public_endpoint_without_connection(self):
        with patch.object(self.endpoint.SocksRoute, 'connect', side_effect=AssertionError('No TCP')):
            host, port = self.endpoint_for()
        self.assertEqual(port, 12000)
        self.assertTrue(host)

    def test_wrong_url_config_and_route_reject_before_connection(self):
        for profile in ({'url':'https://example.invalid/config.json'},
                        {'config_snapshot_sha256':'0' * 64}):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temp:
                path = self.mutated(temp, profile=profile)
                with self.assertRaises(ValueError): self.endpoint_for(path)
        with self.assertRaisesRegex(ValueError, 'selected route differs'):
            self.endpoint_for(port=1088)

    def test_tampered_body_and_private_targets_reject(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.mutated(temp)
            (path.parent / 'body.bin').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'body hash differs'): self.endpoint_for(path)
        for address in ('127.0.0.1', '192.168.1.1', '169.254.1.1', '::1'):
            with self.subTest(address=address), tempfile.TemporaryDirectory() as temp:
                path = self.mutated(temp, address=address)
                with self.assertRaises(ValueError): self.endpoint_for(path)

    def test_current_regional_capability_is_not_implicitly_extended(self):
        for region in ('SG', 'NA', 'EU'):
            with self.subTest(region=region), self.assertRaisesRegex(ValueError, 'Regional lobby selection'):
                self.endpoint_for(lobby_region=region)

    def test_actual_lobby_wiring_reaches_current_sdk_on_same_route(self):
        class SdkBoundaryReached(RuntimeError): pass
        sdk = SimpleNamespace(load_inputs=Mock(side_effect=SdkBoundaryReached('offline boundary')))
        source = SimpleNamespace(app_version='1.13.18', source_snapshot_sha256=CONFIG,
            source_exe_sha256=SOURCE, live_probe_only=True, bounded_world_probe=True)
        def module(name, filename):
            if filename == 'game-source-profile.py':
                return SimpleNamespace(load_profile=lambda **kwargs:source)
            if filename == 'probe-lobby-connection.py': return self.endpoint
            if filename == 'run-nid-sdk-sign-in.py': return sdk
            raise AssertionError('Unexpected module before SDK boundary: ' + filename)
        with patch.object(self.lobby, 'module', side_effect=module):
            with self.assertRaises(SdkBoundaryReached):
                self.lobby.run('fixture@example.invalid', selected_profile='candidate-11318',
                    manifest_path=SNAPSHOT, socks_port=1087, context='sdk-without-nid-info',
                    auth_flow='launcher')
            sdk.load_inputs.assert_called_once()
            kwargs = sdk.load_inputs.call_args.kwargs
            self.assertEqual(kwargs['selected_profile'], 'recovered-release')
            self.assertEqual(kwargs['route'].port, 1087)
            sdk.load_inputs.reset_mock()
            with self.assertRaisesRegex(ValueError, 'selected route differs'):
                self.lobby.run('fixture@example.invalid', selected_profile='candidate-11318',
                    manifest_path=SNAPSHOT, socks_port=1088, context='sdk-without-nid-info',
                    auth_flow='launcher')
            sdk.load_inputs.assert_not_called()


if __name__ == '__main__': unittest.main()
