import importlib.util
from dataclasses import replace
import json
from pathlib import Path
import socket
import struct
import sys
import threading
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.lobby_packets import LobbyVersionPayload, LobbyLoginPayload, LobbyServerListPayload
from vampir_core.lobby_login_probe import exchange_lobby_login
from test_vampir_version_probe import receive_frame, incoming


class LobbyLoginProbeTests(unittest.TestCase):
    def test_selection_sends_list_before_login_and_binds_selected_server_on_same_socket(self):
        version = LobbyVersionPayload(('',) * 5, (0, 3), 1)
        initial = LobbyLoginPayload(('fixture',) * 6, (2, 0, 0, 0), 7)
        request = LobbyServerListPayload(('nm-fixture', 'nid-fixture'), 2, (0, 0))
        report = json.loads(Path('F:/PhoneExit Resources/Vampir/code-clues/lobby-server-list-reader-replay.json').read_text('utf-8'))
        body = bytes(4) + bytes.fromhex(report['cases'][-1]['payload_hex'])[4:]
        for list_code, selected_id, login_code, consumer_error in (
                (0, 251, 0, False), (0, 251, 16, False), (16, 251, 0, False),
                (0, 0, 0, False), (0, 251, 0, True)):
            with self.subTest(list_code=list_code, selected_id=selected_id, login_code=login_code):
                client, server = socket.socketpair()
                server.settimeout(2)
                events, errors, choices, open_sessions = [], [], [], []
                def select_login(response):
                    choices.append(len(response.servers))
                    return replace(initial, integers=(2, 0, selected_id, 0))
                def consume_session(completed):
                    open_sessions.append((client.fileno() >= 0, completed.summary['login_server_id'],
                                          completed.summary['login_result_code']))
                    if consumer_error: raise ValueError('private-callback-fixture')
                def serve():
                    try:
                        events.append(receive_frame(server))
                        server.sendall(incoming(2, bytes(23))[3:])
                        events.append(receive_frame(server))
                        wire = incoming(104, struct.pack('<I', list_code) + body[4:])[3:]
                        for chunk in (wire[:2], wire[2:7], wire[7:]): server.sendall(chunk)
                        if list_code == 0 and selected_id:
                            events.append(receive_frame(server))
                            server.sendall(incoming(4, struct.pack('<I', login_code) + bytes(22))[3:])
                        events.append(server.recv(16))
                    except Exception as error: errors.append(type(error).__name__)
                    finally: server.close()
                worker = threading.Thread(target=serve)
                worker.start()
                result = exchange_lobby_login(client, version, initial, timeout=1,
                    server_list=request, select_login=select_login,
                    on_selected_login=consume_session)
                worker.join(3)
                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                expected = [((1, 0), version.encode(max_payload_size=4096)),
                            ((103, 1), request.encode(max_payload_size=4096))]
                if list_code == 0 and selected_id:
                    expected.append(((3, 2), replace(initial, integers=(2, 0, selected_id, 0)).encode(max_payload_size=4096)))
                    self.assertEqual(result.summary['login_result_code'], login_code)
                    self.assertEqual(result.summary['login_server_id'], selected_id)
                else:
                    self.assertFalse(result.summary['login_sent'])
                    self.assertIsNone(result.response)
                self.assertEqual(events, expected + [b''])
                self.assertEqual(choices, [] if list_code else [2])
                self.assertEqual(open_sessions, [(True, 251, 0)] if list_code == 0 and selected_id and login_code == 0 else [])
                self.assertIsNotNone(result.server_list_response)
                self.assertTrue(result.summary['login_after_server_selection'])
                if consumer_error:
                    self.assertEqual(result.summary['status'], 'protocol_error')
                    self.assertEqual(result.summary['error_type'], 'ValueError')
                    self.assertNotIn('private-callback-fixture', str(result))
                self.assertEqual(client.fileno(), -1)

    def test_socket_login_then_list_id103_id104_on_same_connection(self):
        version = LobbyVersionPayload(('',) * 5, (0, 3), 1)
        login = LobbyLoginPayload(('fixture',) * 6, (2, 0, 0, 0), 7)
        request = LobbyServerListPayload(('nm-fixture', 'nid-fixture'), 2, (0, 0))
        report = json.loads(Path('F:/PhoneExit Resources/Vampir/code-clues/lobby-server-list-reader-replay.json').read_text('utf-8'))
        body = bytes(4) + bytes.fromhex(report['cases'][-1]['payload_hex'])[4:]
        client, server = socket.socketpair()
        server.settimeout(2)
        events, errors = [], []
        def serve():
            try:
                events.append(receive_frame(server)[0])
                server.sendall(incoming(2, bytes(23))[3:])
                events.append(receive_frame(server)[0])
                server.sendall(incoming(4, bytes(26))[3:])
                events.append(receive_frame(server))
                wire = incoming(104, body)[3:]
                for chunk in (wire[:1], wire[1:7], wire[7:]): server.sendall(chunk)
                events.append(server.recv(16))
            except Exception as error: errors.append(type(error).__name__)
            finally: server.close()
        worker = threading.Thread(target=serve)
        worker.start()
        result = exchange_lobby_login(client, version, login, timeout=1, server_list=request)
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(events, [(1, 0), (3, 1), ((103, 2), request.encode(max_payload_size=4096)), b''])
        self.assertEqual(result.summary['status'], 'lobby_server_list_result')
        self.assertEqual(result.summary['server_list_result_code'], 0)
        self.assertEqual((result.summary['server_groups'], result.summary['servers']), (2, 2))
        self.assertEqual(len(result.server_list_response.servers), 2)
        self.assertNotIn('game.invalid', repr(result))

    def test_rejected_login_does_not_send_optional_server_list(self):
        client, server = socket.socketpair()
        server.settimeout(2)
        errors = []
        def serve():
            try:
                receive_frame(server)
                server.sendall(incoming(2, bytes(23))[3:])
                receive_frame(server)
                server.sendall(incoming(4, struct.pack('<I', 1602) + bytes(22))[3:])
                if server.recv(16) != b'': errors.append('unexpected_followup')
            except Exception as error: errors.append(type(error).__name__)
            finally: server.close()
        worker = threading.Thread(target=serve)
        worker.start()
        result = exchange_lobby_login(client, LobbyVersionPayload(('',) * 5, (0, 3), 1),
            LobbyLoginPayload(('',) * 6, (2, 0, 0, 0), 7), timeout=1,
            server_list=LobbyServerListPayload(('', ''), 2, (0, 0)))
        worker.join(3)
        self.assertEqual(errors, [])
        self.assertFalse(result.summary['server_list_sent'])
        self.assertIsNone(result.server_list_response)

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
