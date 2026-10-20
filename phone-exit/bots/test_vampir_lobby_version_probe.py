import importlib.util
import json
from pathlib import Path
import socket
import struct
import sys
import threading
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.lobby_packets import LobbyVersionPayload
from vampir_core.lobby_version_probe import exchange_lobby_version
from vampir_core.windows_version import WindowsVersion
from test_vampir_version_probe import incoming, receive_frame


class LobbyVersionProbeTests(unittest.TestCase):
    def test_real_socket_fragmented_response_without_login(self):
        payload = LobbyVersionPayload(('app-fixture', 'os-fixture', 'host-fixture', 'nm-fixture', ''), (0, 3), 1)
        client, server = socket.socketpair()
        server.settimeout(2)
        captures, errors = [], []
        def serve():
            try:
                captures.append(receive_frame(server))
                response = incoming(2, struct.pack('<IBQQH', 0, 1, 7, 8, 9))[3:]
                for chunk in (response[:2], response[2:9], response[9:]): server.sendall(chunk)
                captures.append(server.recv(64))
            except Exception as exc: errors.append(type(exc).__name__)
            finally: server.close()
        worker = threading.Thread(target=serve)
        worker.start()
        result = exchange_lobby_version(client, payload, timeout=1)
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(captures, [((1, 0), payload.encode(max_payload_size=4096)), b''])
        self.assertEqual(result['status'], 'lobby_version_result')
        self.assertEqual(result['result_code'], 0)
        self.assertTrue(result['flag_14'])
        self.assertFalse(result['login_sent'])
        self.assertFalse(result['server_list_sent'])
        self.assertEqual(client.fileno(), -1)
        self.assertNotIn('nm-fixture', json.dumps(result))

    def test_timeout_bad_body_and_eof_close(self):
        payload = LobbyVersionPayload(('',) * 5, (0, 3), 1)
        for wire, status in ((None, 'timeout'), (b'bad', None), (b'', 'server_closed')):
            client, server = socket.socketpair()
            try:
                if wire == b'': server.shutdown(socket.SHUT_WR)
                elif wire is not None: server.sendall(incoming(2, wire)[3:])
                if status is None:
                    result = exchange_lobby_version(client, payload, timeout=0.02)
                    self.assertEqual(result['status'], 'protocol_error')
                    self.assertEqual(result['error_type'], 'ValueError')
                    self.assertEqual(result['last_body_size'], 3)
                else:
                    self.assertEqual(exchange_lobby_version(client, payload, timeout=0.02)['status'], status)
                self.assertEqual(client.fileno(), -1)
            finally: server.close()

    def test_explicit_source_fields_and_native_cdn_connect_handoff(self):
        spec = importlib.util.spec_from_file_location('test_lobby_probe_source', HERE / 'vampir-headless/probe-lobby-version.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        version = WindowsVersion(10, 0, 26200, 1, 256)
        payload = tool.prepare_version(app_version='1.12.14', windows_version=version,
            computer_name='fixture-host', nm_device_key='fixture-nm')
        self.assertEqual(payload.strings, ('1.12.14', version.suffix(), 'fixture-host', 'fixture-nm', ''))
        self.assertEqual(payload.raw_bytes, (0, 3))
        self.assertEqual(payload.raw_70, 1)
        with self.assertRaises(ValueError):
            tool.prepare_version(app_version='1.12.14', windows_version=None, computer_name='fixture', nm_device_key='fixture')
        report = json.loads(Path('F:/PhoneExit Resources/Vampir/code-clues/cdn-lobby-endpoint-replay.json').read_text('utf-8'))
        spec = importlib.util.spec_from_file_location('test_cdn_lobby_replay', HERE / 'resource-tools/vampir/replay-cdn-lobby-endpoint.py')
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        self.assertEqual(native.build(), report)
        self.assertEqual(len(report['cases']), 20)
        for case in report['cases']:
            self.assertEqual(case['endpoint']['host'], case['global_host'])
            self.assertEqual(case['endpoint']['port'], case['global_port_uint32'] & 65535)


if __name__ == '__main__': unittest.main()
