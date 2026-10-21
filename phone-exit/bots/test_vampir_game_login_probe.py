import socket
import struct
import threading
import unittest
from unittest.mock import patch

from test_vampir_login_flow import VERSION, LOGIN, RESULT, FIXTURE
from test_vampir_version_probe import incoming, receive_frame
from vampir_core.game_login_probe import exchange_game_login
from test_vampir_selection_flow import list_body, FIXTURE as SELECTION_FIXTURE
from vampir_core.session_clock import LobbyPingClock


class GameLoginProbeTests(unittest.TestCase):
    def attempt(self, *, version_body=RESULT, login_body=None, wait_for_login=True, read_character_list=False, character_body=None, ping_clock=None, character_index=None, wait_for_select=False, select_body=None, select_fields=None):
        client, server = socket.socketpair()
        server.settimeout(2)
        captures, errors = [], []
        ping_bodies = []
        selection_bodies = []
        def serve():
            try:
                captures.append(receive_frame(server)[0])
                if ping_clock is not None:
                    header, body = receive_frame(server)
                    captures.append(header)
                    ping_bodies.append(body)
                server.sendall(incoming(2, version_body))
                if wait_for_login:
                    captures.append(receive_frame(server)[0])
                    server.sendall(incoming(4, login_body))
                    if character_body is not None:
                        captures.append(receive_frame(server)[0])
                        server.sendall(incoming(102, character_body))
                        if wait_for_select:
                            header,body = receive_frame(server)
                            captures.append(header)
                            selection_bodies.append(body)
                            if select_body is not None: server.sendall(incoming(110,select_body))
                while server.recv(32): pass
            except BaseException as error: errors.append(type(error).__name__)
            finally: server.close()
        worker = threading.Thread(target=serve)
        worker.start()
        with patch('vampir_core.game_login_probe.time.time_ns', return_value=1792600142863000000):
            result = exchange_game_login(client, VERSION, LOGIN, timeout=1,
                read_character_list=read_character_list, ping_clock=ping_clock, character_index=character_index)
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(client.fileno(), -1)
        if ping_clock is not None:
            self.assertEqual(ping_bodies, [struct.pack('<QQ', 1792632542863, 1792632542863)])
        if select_fields is not None:
            self.assertEqual(selection_bodies,[struct.pack('<QIQ',*select_fields)])
        return result, captures

    def test_early_ping_precedes_login_and_preserves_list_sequence(self):
        result, captures = self.attempt(login_body=bytes.fromhex(FIXTURE['login_result_hex']),
            ping_clock=LobbyPingClock(540), read_character_list=True,
            character_body=list_body(keys=(11,), preferred=11))
        self.assertEqual(captures, [(1, 0), (16, 1), (3, 2), (101, 3)])
        self.assertEqual(result['character_count'], 1)

    def test_early_ping_does_not_override_version_refusal(self):
        result, captures = self.attempt(version_body=struct.pack('<I', 16) + RESULT[4:],
            wait_for_login=False, ping_clock=LobbyPingClock(540))
        self.assertEqual(captures, [(1, 0), (16, 1)])
        self.assertFalse(result['login_result_received'])

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

    def test_invalid_state_is_reported_without_retry_or_character_request(self):
        body = struct.pack('<I', 16) + bytes.fromhex(FIXTURE['login_result_hex'])[4:]
        result, captures = self.attempt(login_body=body)
        self.assertEqual(captures, [(1, 0), (3, 1)])
        self.assertEqual(result['login_result_code'], 16)
        self.assertEqual(result['login_result_key'], 'InvalidState')
        self.assertEqual(result['login_error_message'], 'Недопустимое состояние при входе.')
        self.assertFalse(result['character_list_sent'])
        self.assertFalse(result['game_session_ready'])

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

    def test_explicit_list_entry_keeps_same_socket_sequence_and_redacts_characters(self):
        result, captures = self.attempt(login_body=bytes.fromhex(FIXTURE['login_result_hex']),
            read_character_list=True, character_body=list_body(keys=(11,), preferred=11))
        self.assertEqual(captures, [(1, 0), (3, 1), (101, 2)])
        self.assertEqual(result['status'], 'character_list_result')
        self.assertTrue(result['character_list_sent'])
        self.assertTrue(result['character_list_received'])
        self.assertEqual(result['character_list_result_code'], 0)
        self.assertEqual(result['character_count'], 1)
        self.assertEqual(result['preferred_character_index'], 0)
        self.assertFalse(result['character_select_sent'])
        self.assertFalse(result['game_session_ready'])

    def test_list_entry_option_never_sends_on_invalid_packet_version(self):
        body = struct.pack('<I', 1) + bytes.fromhex(FIXTURE['login_result_hex'])[4:]
        result, captures = self.attempt(login_body=body, read_character_list=True)
        self.assertEqual(captures, [(1, 0), (3, 1)])
        self.assertEqual(result['login_result_key'], 'InvalidPacketVersion')
        self.assertFalse(result['character_list_sent'])
        self.assertFalse(result['character_list_received'])

    def test_list_refusal_closes_and_never_selects_or_retries(self):
        result, captures = self.attempt(login_body=bytes.fromhex(FIXTURE['login_result_hex']),
            read_character_list=True, character_body=list_body(code=16))
        self.assertEqual(captures, [(1, 0), (3, 1), (101, 2)])
        self.assertEqual(result['character_list_result_code'], 16)
        self.assertFalse(result['character_select_sent'])


    def test_explicit_selection_keeps_same_socket_and_selects_only_requested_record(self):
        body=bytes.fromhex(SELECTION_FIXTURE['select_result_hex'])
        result,captures=self.attempt(login_body=bytes.fromhex(FIXTURE['login_result_hex']),
            read_character_list=True,character_body=list_body(),character_index=1,
            wait_for_select=True,select_body=body,select_fields=(22,0,42))
        self.assertEqual(captures,[(1,0),(3,1),(101,2),(109,3)])
        self.assertEqual(result['status'],'character_select_result')
        self.assertEqual(result['character_count'],2)
        self.assertEqual(result['character_select_result_code'],0)
        self.assertTrue(result['character_select_result_received'])
        self.assertTrue(result['selection_body_fully_decoded'])
        self.assertEqual(result['character_select_body_size'],len(body))
        self.assertFalse(result['game_session_ready'])

    def test_empty_or_short_list_never_sends_selection(self):
        for keys,index in (((),0),((11,),1)):
            result,captures=self.attempt(login_body=bytes.fromhex(FIXTURE['login_result_hex']),
                read_character_list=True,character_body=list_body(keys=keys),character_index=index)
            self.assertEqual(captures,[(1,0),(3,1),(101,2)])
            self.assertEqual(result['status'],'character_selection_not_sent')
            self.assertEqual(result['selection_error'],'index_out_of_range')
            self.assertFalse(result['character_select_sent'])

    def test_selection_refusal_preserves_list_summary_and_does_not_retry(self):
        body=struct.pack('<I',16)+bytes.fromhex(SELECTION_FIXTURE['select_result_hex'])[4:]
        result,captures=self.attempt(login_body=bytes.fromhex(FIXTURE['login_result_hex']),
            read_character_list=True,character_body=list_body(),character_index=0,
            wait_for_select=True,select_body=body)
        self.assertEqual(captures,[(1,0),(3,1),(101,2),(109,3)])
        self.assertEqual(result['character_list_result_code'],0)
        self.assertEqual(result['character_count'],2)
        self.assertEqual(result['character_select_result_code'],16)
        self.assertTrue(result['character_select_result_received'])
        self.assertFalse(result['game_session_ready'])

    def test_malformed_selection_preserves_list_summary_without_exposing_body(self):
        result,_=self.attempt(login_body=bytes.fromhex(FIXTURE['login_result_hex']),
            read_character_list=True,character_body=list_body(),character_index=0,
            wait_for_select=True,select_body=b'private-malformed-selection')
        self.assertEqual(result['status'],'connection_processing_failed')
        self.assertEqual(result['selection_error'],'invalid_response')
        self.assertEqual(result['character_count'],2)
        self.assertFalse(result['character_select_result_received'])
        self.assertNotIn('private-malformed-selection',str(result))

    def test_selection_timeout_does_not_repeat_the_request(self):
        result,captures=self.attempt(login_body=bytes.fromhex(FIXTURE['login_result_hex']),
            read_character_list=True,character_body=list_body(),character_index=0,wait_for_select=True)
        self.assertEqual(captures,[(1,0),(3,1),(101,2),(109,3)])
        self.assertFalse(result['character_select_result_received'])
        self.assertEqual(result['selection_error'],'request_timeout')


if __name__ == '__main__': unittest.main()
