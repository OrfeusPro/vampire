import importlib.util
from pathlib import Path
import socket
import struct
import threading
import unittest

from test_vampir_login_flow import VERSION, LOGIN, RESULT, FIXTURE
from test_vampir_version_probe import incoming, receive_frame
from test_vampir_selection_flow import list_body


class DiagnosticListTests(unittest.TestCase):
    def test_request_after_rejected_login_and_never_select(self):
        path = Path(__file__).parent / 'vampir-headless/diagnose-list-after-login.py'
        spec = importlib.util.spec_from_file_location('diagnostic_list', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        for list_response in (None, list_body(code=16), list_body(keys=(11,), preferred=11)):
            with self.subTest(list_response=list_response is not None):
                client, server = socket.socketpair()
                server.settimeout(2)
                events, errors = [], []
                def serve():
                    try:
                        events.append(receive_frame(server)[0])
                        server.sendall(incoming(2, RESULT))
                        events.append(receive_frame(server)[0])
                        body = struct.pack('<I', 16) + bytes.fromhex(FIXTURE['login_result_hex'])[4:]
                        server.sendall(incoming(4, body))
                        header, request = receive_frame(server)
                        events.append(header)
                        self.assertEqual(request, b'')
                        if list_response is not None:
                            server.sendall(incoming(102, list_response))
                            self.assertEqual(server.recv(32), b'')
                    except Exception as error: errors.append(type(error).__name__)
                    finally: server.close()
                worker = threading.Thread(target=serve)
                worker.start()
                result = tool.exchange(client, VERSION, LOGIN, timeout=1, read_character_list=True)
                worker.join(3)
                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(events, [(1, 0), (3, 1), (101, 2)])
                self.assertEqual(result['login_result_code'], 16)
                self.assertTrue(result['character_list_sent'])
                self.assertFalse(result['game_session_ready'])
                self.assertFalse(result['character_select_sent'])
                self.assertEqual(result['status'], 'server_closed' if list_response is None else 'character_list_result')


if __name__ == '__main__': unittest.main()
