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
from vampir_core.lobby_packets import LobbyVersionPayload, LobbyLoginPayload
from vampir_core.lobby_login_probe import exchange_lobby_login
from test_vampir_version_probe import receive_frame, incoming


class LobbyLoginProbeTests(unittest.TestCase):
    def test_socket_version_then_login_and_bounded_response_no_followup(self):
        version = LobbyVersionPayload(('version-fixture',) + ('',) * 4, (0, 3), 1)
        login = LobbyLoginPayload(('player-fixture', 'sdk-secret-fixture', 'nm-fixture', '', 'nid-fixture', ''), (2, 0, 0, 0), 7)
        for result_code in (0, 1602):
            client, server = socket.socketpair()
            server.settimeout(2)
            events, errors = [], []
            def serve():
                try:
                    events.append(receive_frame(server))
                    server.sendall(incoming(2, struct.pack('<IBQQH', 0, 0, 1, 2, 3))[3:])
                    events.append(receive_frame(server))
                    strings = [b'private-session-a', b'private-session-b', b'', b'', b'']
                    body = struct.pack('<III', result_code, 7, 8) + b''.join(struct.pack('<H', len(s)) + s for s in strings) + struct.pack('<I', 9)
                    wire = incoming(4, body)[3:]
                    for chunk in (wire[:2], wire[2:9], wire[9:]): server.sendall(chunk)
                    events.append(server.recv(16))
                except Exception as error: errors.append(type(error).__name__)
                finally: server.close()
            worker = threading.Thread(target=serve)
            worker.start()
            result = exchange_lobby_login(client, version, login, timeout=1)
            worker.join(3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(events, [((1, 0), version.encode(max_payload_size=4096)),
                ((3, 1), login.encode(max_payload_size=4096)), b''])
            self.assertEqual(result.summary['login_result_code'], result_code)
            self.assertTrue(result.summary['login_sent'])
            self.assertFalse(result.summary['server_list_sent'])
            self.assertEqual(result.response.strings[:2], ('private-session-a', 'private-session-b'))
            self.assertNotIn('private-session', repr(result))
            self.assertNotIn('sdk-secret-fixture', json.dumps(result.summary))
            self.assertEqual(client.fileno(), -1)

    def test_version_rejection_or_numeric_flag_never_send_login(self):
        version = LobbyVersionPayload(('',) * 5, (0, 3), 1)
        login = LobbyLoginPayload(('',) * 6, (2, 0, 0, 0), 7)
        for code, flag, status in ((1, 0, 'version_rejected'), (0, 1, 'additional_numeric_context_required')):
            client, server = socket.socketpair()
            server.sendall(incoming(2, struct.pack('<IBQQH', code, flag, 0, 0, 0))[3:])
            try:
                result = exchange_lobby_login(client, version, login, timeout=0.2)
                self.assertEqual(result.summary['status'], status)
                self.assertFalse(result.summary['login_sent'])
                self.assertIsNone(result.response)
                self.assertEqual(receive_frame(server)[0], (1, 0))
                self.assertEqual(server.recv(16), b'')
            finally: server.close()

    def test_context_index_reproduces_without_assigning_candidate_object_types(self):
        report = json.loads(Path('F:/PhoneExit Resources/Vampir/code-clues/lobby-login-context-index.json').read_text('utf-8'))
        spec = importlib.util.spec_from_file_location('test_lobby_context_index', HERE / 'resource-tools/vampir/build-lobby-login-context-index.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        self.assertEqual(tool.build(), report)
        self.assertEqual(len(report['calls']), 49)
        self.assertEqual(report['failed_roots'], [])


if __name__ == '__main__': unittest.main()
