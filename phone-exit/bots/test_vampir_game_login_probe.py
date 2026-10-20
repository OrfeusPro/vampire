import socket
import struct
import threading
import unittest

from test_vampir_login_flow import VERSION, LOGIN, RESULT, FIXTURE
from test_vampir_version_probe import incoming, receive_frame
from vampir_core.game_login_probe import exchange_game_login


class GameLoginProbeTests(unittest.TestCase):
    def attempt(self, *, version_body=RESULT, login_body=None, wait_for_login=True):
        client, server = socket.socketpair()
        server.settimeout(2)
        captures, errors = [], []
        def serve():
            try:
                captures.append(receive_frame(server)[0])
                server.sendall(incoming(2, version_body))
                if wait_for_login:
                    captures.append(receive_frame(server)[0])
                    server.sendall(incoming(4, login_body))
                while server.recv(32): pass
            except BaseException as error: errors.append(type(error).__name__)
            finally: server.close()
        worker = threading.Thread(target=serve)
        worker.start()
        result = exchange_game_login(client, VERSION, LOGIN, timeout=1)
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(client.fileno(), -1)
        return result, captures

    def test_version_then_login_same_socket_and_sequence_without_character_request(self):
        body = bytes.fromhex(FIXTURE['login_result_hex'])
        result, captures = self.attempt(login_body=body)
        self.assertEqual(captures, [(1, 0), (3, 1)])
        self.assertEqual((result['version_result_code'], result['login_result_code']), (0, 0))
        self.assertEqual(result['last_body_size'], len(body))
        self.assertTrue(result['login_result_received'])
        self.assertFalse(result['character_list_sent'])
        self.assertFalse(result['game_session_ready'])
        self.assertNotIn('token-fixture', str(result))

    def test_login_refusal_keeps_both_result_codes_after_close(self):
        body = struct.pack('<I', 12345) + bytes.fromhex(FIXTURE['login_result_hex'])[4:]
        result, captures = self.attempt(login_body=body)
        self.assertEqual(captures, [(1, 0), (3, 1)])
        self.assertEqual((result['version_result_code'], result['login_result_code']), (0, 12345))
        self.assertEqual(result['login_error'], 'unsupported_result_code')

    def test_blocked_ip_is_reported_without_guessing_region_or_retry(self):
        body = struct.pack('<I', 58) + bytes.fromhex(FIXTURE['login_result_hex'])[4:]
        result, captures = self.attempt(login_body=body)
        self.assertEqual(captures, [(1, 0), (3, 1)])
        self.assertEqual(result['login_result_key'], 'BlockedIp')
        self.assertEqual(result['login_error_message'], 'Доступ с этого IP ограничен сервером.')
        self.assertFalse(result['character_list_sent'])

    def test_version_refusal_never_sends_login(self):
        result, captures = self.attempt(version_body=struct.pack('<I', 23456) + RESULT[4:], wait_for_login=False)
        self.assertEqual(captures, [(1, 0)])
        self.assertEqual(result['version_result_code'], 23456)
        self.assertFalse(result['login_result_received'])

    def test_invalid_login_body_reports_generic_failure(self):
        result, _ = self.attempt(login_body=b'private-malformed-data')
        self.assertEqual(result['status'], 'connection_processing_failed')
        self.assertEqual(result['version_result_code'], 0)
        self.assertFalse(result['login_result_received'])
        self.assertNotIn('private-malformed-data', str(result))
        self.assertFalse(result['byte_counts_complete'])

    def test_no_response_times_out_and_closes_without_retry(self):
        client, server = socket.socketpair()
        try:
            result = exchange_game_login(client, VERSION, LOGIN, timeout=0.02)
            self.assertEqual(result['error'], 'login_timeout')
            self.assertFalse(result['login_result_received'])
            self.assertEqual(client.fileno(), -1)
            server.settimeout(1)
            self.assertEqual(receive_frame(server)[0], (1, 0))
            self.assertEqual(server.recv(32), b'')
        finally:
            client.close()
            server.close()


if __name__ == '__main__': unittest.main()
