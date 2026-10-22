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
from vampir_core.world_move_start import SOURCE_SHA256
from vampir_core.character_select_result import decode_character_select_result
from test_vampir_world_entry_flow import reserve_body, finish_body


class GameLoginProbeTests(unittest.TestCase):
    def attempt(self, *, version_body=RESULT, login_body=None, wait_for_login=True, read_character_list=False, character_body=None, ping_clock=None, character_index=None, wait_for_select=False, select_body=None, select_fields=None, other_packets=(), read_world_start=False, world_reserve_body=None, world_start_body=None, read_world_finish=False, world_finish_body=None, observe_world_seconds=0, advance_clock=False, world_observer=None, after_finish_packets=(), tutorial_observer=None, before_finish_packets=(), ack_initial_tutorial=False, expected_tutorial_ack=False, tutorial_ack_response=None, read_quest_list=False, quest_response=None, quest_observer=None, quest_wire_observer=None):
        client, server = socket.socketpair()
        server.settimeout(2)
        captures, errors = [], []
        ping_bodies = []
        selection_bodies = []
        clock_advanced=[False]
        def serve():
            try:
                captures.append(receive_frame(server)[0])
                if ping_clock is not None:
                    header, body = receive_frame(server)
                    captures.append(header)
                    ping_bodies.append(body)
                    if observe_world_seconds:server.sendall(incoming(17,struct.pack('<IQ',0,0)))
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
                            if other_packets:
                                server.sendall(b''.join(incoming(pid,b'') for pid in other_packets))
                            if select_body is not None:
                                packet = incoming(110,select_body)
                                if world_reserve_body is not None:
                                    packet += incoming(202,world_reserve_body)
                                server.sendall(packet)
                                if world_reserve_body is not None and struct.unpack_from('<I',world_reserve_body)[0]==0:
                                    header, body = receive_frame(server)
                                    captures.append(header)
                                    selected = decode_character_select_result(select_body,
                                        max_payload_size=1048576,max_collection_items=4096)
                                    if body != struct.pack('<Q',selected.player.at(8)):
                                        raise AssertionError('Unexpected world start body')
                                    if world_start_body is not None:
                                        server.sendall(incoming(204,world_start_body))
                                        if read_world_finish and struct.unpack_from('<I',world_start_body)[0]==0:
                                            header, body=receive_frame(server)
                                            captures.append(header)
                                            if body!=b'':raise AssertionError('Nonempty finish request')
                                            if world_finish_body is not None:
                                                clock_advanced[0]=advance_clock
                                                server.sendall(b''.join(incoming(pid,payload) for pid,payload in before_finish_packets)+incoming(206,world_finish_body)+b''.join(
                                                    incoming(pid,payload) for pid,payload in after_finish_packets))
                                                if observe_world_seconds and advance_clock:
                                                    header,body=receive_frame(server)
                                                    captures.append(header)
                                                    if header[0]!=16:raise AssertionError('Expected periodic Ping')
                                                    server.sendall(incoming(17,struct.pack('<IQ',0,0)))
                if expected_tutorial_ack:
                    header, body = receive_frame(server)
                    captures.append(header)
                    if header[0] != 9903 or body != struct.pack('<IIB', 1001, 2, 0):
                        raise AssertionError('Unexpected initial tutorial acknowledgement')
                    if tutorial_ack_response is not None:
                        server.sendall(incoming(9904, tutorial_ack_response))
                if read_quest_list:
                    header, body = receive_frame(server)
                    captures.append(header)
                    if header[0] != 1801 or body != bytes(9):
                        raise AssertionError('Unexpected quest list diagnostic')
                    if quest_response is not None: server.sendall(incoming(1802, quest_response))
                while server.recv(32): pass
            except BaseException as error: errors.append(type(error).__name__)
            finally: server.close()
        worker = threading.Thread(target=serve)
        worker.start()
        with patch('vampir_core.game_login_probe.time.time_ns', side_effect=lambda:1792600142863000000+(6001000000 if clock_advanced[0] else 0)):
            result = exchange_game_login(client, VERSION, LOGIN, timeout=1,
                read_character_list=read_character_list, ping_clock=ping_clock, character_index=character_index,
                read_world_start=read_world_start, read_world_finish=read_world_finish, observe_world_seconds=observe_world_seconds, world_observer=world_observer, tutorial_observer=tutorial_observer, ack_initial_tutorial=ack_initial_tutorial, read_quest_list=read_quest_list, quest_observer=quest_observer, quest_wire_observer=quest_wire_observer, source_sha256=SOURCE_SHA256 if read_world_start else None)
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(client.fileno(), -1)
        if ping_clock is not None:
            self.assertEqual(ping_bodies, [struct.pack('<QQ', 1792632542863, 1792632542863)])
        if select_fields is not None:
            self.assertEqual(selection_bodies,[struct.pack('<QIQ',*select_fields)])
        return result, captures

    def world_attempt(self, **kwargs):
        return self.attempt(login_body=bytes.fromhex(FIXTURE['login_result_hex']),
            read_character_list=True,character_body=list_body(),character_index=0,
            wait_for_select=True,select_body=bytes.fromhex(SELECTION_FIXTURE['select_result_hex']),
            read_world_start=True,**kwargs)

    def test_world_start_after_coalesced_selection_and_reserve_uses_same_sequence(self):
        result,captures=self.world_attempt(world_reserve_body=reserve_body(),
            world_start_body=struct.pack('<IIIIIBBQ',0,1,2,3,4,0,0,77))
        self.assertEqual(captures,[(1,0),(3,1),(101,2),(109,3),(203,4)])
        self.assertEqual(result['status'],'world_start_result')
        self.assertEqual(result['world_start_result_code'],0)
        self.assertTrue(result['world_reserve_received'])
        self.assertTrue(result['world_start_received'])
        self.assertFalse(result['world_reserve_full_body_validated'])
        self.assertFalse(result['game_session_ready'])
        self.assertNotIn('opaque-private-suffix',str(result))

    def test_world_finish_uses_same_connection_and_does_not_claim_readiness(self):
        result,captures=self.world_attempt(world_reserve_body=reserve_body(),
            world_start_body=struct.pack('<IIIIIBBQ',0,9,2,3,4,0,0,77),
            read_world_finish=True,world_finish_body=finish_body())
        self.assertEqual(captures,[(1,0),(3,1),(101,2),(109,3),(203,4),(205,5)])
        self.assertEqual(result['status'],'world_finish_result')
        self.assertEqual(result['world_finish_result_code'],0)
        self.assertTrue(result['server_target_position_received'])
        self.assertFalse(result['game_session_ready'])
        self.assertFalse(result['world_reserve_full_body_validated'])

    def test_explicit_quest_list_read_on_world_connection(self):
        from test_vampir_quest_list import fixture
        for code in (0, 9):
            events = []
            body = bytearray(fixture());body[0] = code
            result, captures = self.world_attempt(world_reserve_body=reserve_body(),
                world_start_body=struct.pack('<IIIIIBBQ', 0, 9, 2, 3, 4, 0, 0, 77),
                read_world_finish=True, world_finish_body=finish_body(),
                ping_clock=LobbyPingClock(540), observe_world_seconds=.3,
                read_quest_list=True, quest_response=bytes(body), quest_observer=events.append)
            self.assertEqual(captures[-1], (1801, 7))
            self.assertEqual(result['status'], 'quest_list_result')
            self.assertEqual(result['quest_list_state'], 'received' if code == 0 else 'rejected')
            self.assertEqual(result['quest_list_result_code'], code)
            self.assertEqual(result['quest_count'], 0)
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0].item_changes.counts, (0, 0, 0, 0))
            self.assertIsNone(events[1])
            self.assertFalse(result['game_session_ready'])

    def test_quest_list_no_reply_is_unknown(self):
        result, captures = self.world_attempt(world_reserve_body=reserve_body(),
            world_start_body=struct.pack('<IIIIIBBQ', 0, 9, 2, 3, 4, 0, 0, 77),
            read_world_finish=True, world_finish_body=finish_body(),
            ping_clock=LobbyPingClock(540), observe_world_seconds=.05, read_quest_list=True)
        self.assertEqual(captures[-1], (1801, 7))
        self.assertEqual(result['quest_list_state'], 'unknown')
        self.assertNotIn('quest_count', result)

    def test_rejected_quest_body_can_be_observed_before_decoder_failure(self):
        wire = []
        result, _ = self.world_attempt(world_reserve_body=reserve_body(),
            world_start_body=struct.pack('<IIIIIBBQ', 0, 9, 2, 3, 4, 0, 0, 77),
            read_world_finish=True, world_finish_body=finish_body(),
            ping_clock=LobbyPingClock(540), observe_world_seconds=.3,
            read_quest_list=True, quest_response=b'\0\0\0\0', quest_wire_observer=wire.append)
        self.assertEqual(wire, [bytes(4)])
        self.assertEqual(result['status'], 'connection_processing_failed')
        self.assertEqual(result['quest_list_state'], 'unknown')
        self.assertEqual(result['quest_list_decode_error'], 'Truncated quest list body')
        self.assertEqual(result['quest_list_decode_body_size'], 4)
        self.assertEqual(result['other_packet_counts']['1802'], 1)

    def test_explicit_initial_tutorial_ack_after_world_finish(self):
        snapshot = b'\0\1\0' + struct.pack('<IIIB', 1001, 0, 0, 1)
        for code in (0, 4223):
            result, captures = self.world_attempt(world_reserve_body=reserve_body(),
                world_start_body=struct.pack('<IIIIIBBQ', 0, 9, 2, 3, 4, 0, 0, 77),
                read_world_finish=True, world_finish_body=finish_body(),
                ping_clock=LobbyPingClock(540), observe_world_seconds=.3,
                before_finish_packets=((9905, snapshot),), ack_initial_tutorial=True,
                expected_tutorial_ack=True,
                tutorial_ack_response=struct.pack('<IIIIBBB', code, 1001, 2, 0, 1, 0, 0))
            self.assertEqual(captures[-1], (9903, 7))
            self.assertEqual(result['status'], 'initial_tutorial_ack_result')
            self.assertEqual(result['initial_tutorial_ack_state'], 'accepted' if code == 0 else 'rejected')
            self.assertEqual(result['initial_tutorial_ack_result_code'], code)
            self.assertEqual(result['initial_tutorial_ack_response'], dict(raw08=1001,
                raw0c=2, raw10=0, state=1, raw30=False, raw31=False))
            self.assertFalse(result['game_session_ready'])

    def test_initial_tutorial_ack_without_reply_has_unknown_outcome(self):
        result, captures = self.world_attempt(world_reserve_body=reserve_body(),
            world_start_body=struct.pack('<IIIIIBBQ', 0, 9, 2, 3, 4, 0, 0, 77),
            read_world_finish=True, world_finish_body=finish_body(),
            ping_clock=LobbyPingClock(540), observe_world_seconds=.05,
            before_finish_packets=((9905, b'\0\1\0'+struct.pack('<IIIB', 1001, 0, 0, 1)),),
            ack_initial_tutorial=True, expected_tutorial_ack=True)
        self.assertEqual(captures[-1], (9903, 7))
        self.assertEqual(result['initial_tutorial_ack_state'], 'unknown')
        self.assertIsNone(result['initial_tutorial_ack_result_code'])
        self.assertNotIn('initial_tutorial_ack_response', result)

    def test_initial_tutorial_ack_is_opt_in_and_requires_snapshot(self):
        for opted_in, packets in ((False, ((9905, b'\0\1\0'+struct.pack('<IIIB', 1001, 0, 0, 1)),)),
                                  (True, ())):
            result, captures = self.world_attempt(world_reserve_body=reserve_body(),
                world_start_body=struct.pack('<IIIIIBBQ', 0, 9, 2, 3, 4, 0, 0, 77),
                read_world_finish=True, world_finish_body=finish_body(),
                ping_clock=LobbyPingClock(540), observe_world_seconds=.05,
                before_finish_packets=packets, ack_initial_tutorial=opted_in)
            self.assertNotIn(9903, [header[0] for header in captures])
            if opted_in: self.assertEqual(result['initial_tutorial_ack_state'], 'waiting_snapshot')
            else: self.assertNotIn('initial_tutorial_ack_state', result)

    def test_bounded_world_observation_sends_periodic_ping_and_receives_reply(self):
        result,captures=self.world_attempt(world_reserve_body=reserve_body(),
            world_start_body=struct.pack('<IIIIIBBQ',0,9,2,3,4,0,0,77),
            read_world_finish=True,world_finish_body=finish_body(),
            ping_clock=LobbyPingClock(540),observe_world_seconds=.05,advance_clock=True)
        self.assertEqual(captures,[(1,0),(16,1),(3,2),(101,3),(109,4),(203,5),(205,6),(16,7)])
        self.assertEqual(result['status'],'world_observation_complete')
        self.assertEqual(result['periodic_ping_queued'],1)
        self.assertEqual(result['ping_results_received'],2)
        self.assertTrue(result['world_observation_completed'])
        self.assertTrue(result['server_target_position_received'])
        self.assertFalse(result['game_session_ready'])

    def test_map_observer_receives_position_then_cleanup_without_public_coordinates(self):
        events=[]
        result,_=self.world_attempt(world_reserve_body=reserve_body(),
            world_start_body=struct.pack('<IIIIIBBQ',0,10011,2,3,4,0,0,77),
            read_world_finish=True,world_finish_body=finish_body(),world_observer=events.append)
        self.assertEqual(len(events),2)
        self.assertEqual(events[0].world_id,10011)
        self.assertEqual(events[0].vector.finite_values(),(1.5,-2.25,-0.0))
        self.assertIsNone(events[1])
        self.assertNotIn('target_position',result)

    def test_coalesced_move_updates_only_selected_character_before_first_observer(self):
        events=[]
        selected=bytearray.fromhex(SELECTION_FIXTURE['select_result_hex'])
        struct.pack_into('<Q',selected,4,42)
        result,captures=self.attempt(login_body=bytes.fromhex(FIXTURE['login_result_hex']),
            read_character_list=True,character_body=list_body(),character_index=0,
            wait_for_select=True,select_body=bytes(selected),read_world_start=True,
            world_reserve_body=reserve_body(),world_start_body=struct.pack('<IIIIIBBQ',0,10010,2,3,4,0,0,77),
            read_world_finish=True,world_finish_body=finish_body(),world_observer=events.append,
            after_finish_packets=((307,struct.pack('<Qff',43,987,654)),(307,struct.pack('<Qff',42,12,34))))
        self.assertEqual(result['status'],'world_finish_result')
        self.assertEqual(result['own_xy_target_updates'],1)
        self.assertEqual(len(events),2)
        self.assertEqual(events[0].vector.finite_values(),(12,34,-0.0))
        self.assertEqual(events[0].source,'character_move_notify_xy_retained_z')
        self.assertIsNone(events[1])
        self.assertEqual([pid for pid,_ in captures],[1,3,101,109,203,205])
        self.assertNotIn('987',str(result))

    def test_world_finish_refusal_and_timeout(self):
        for body in (finish_body(16),None):
            result,captures=self.world_attempt(world_reserve_body=reserve_body(),
                world_start_body=struct.pack('<IIIIIBBQ',0,9,2,3,4,0,0,77),
                read_world_finish=True,world_finish_body=body)
            self.assertEqual(captures[-1],(205,5))
            self.assertFalse(result['server_target_position_received'])
            self.assertEqual(result['world_entry_error'],
                'finish_result_rejected' if body else 'world_entry_timeout')

    def test_tutorial_notifications_are_deferred_until_finish_and_keep_order(self):
        events=[]
        first=struct.pack('<BHIIIB',1,1,1001,2,0,1)
        second=struct.pack('<BHIIIB',0,1,1002,3,4,2)
        result,captures=self.world_attempt(world_reserve_body=reserve_body(),
            world_start_body=struct.pack('<IIIIIBBQ',0,10010,2,3,4,0,0,77),
            read_world_finish=True,world_finish_body=finish_body(),tutorial_observer=events.append,
            before_finish_packets=((9905,first),),after_finish_packets=((9905,second),))
        self.assertEqual([e.records[0].raw08 for e in events[:-1]],[1001,1002])
        self.assertIsNone(events[-1]);self.assertEqual(result['tutorial_notifications_decoded'],2)
        self.assertEqual([pid for pid,_ in captures],[1,3,101,109,203,205])

    def test_bad_tutorial_body_closes_without_observer_data(self):
        events=[]
        result,_=self.world_attempt(world_reserve_body=reserve_body(),
            world_start_body=struct.pack('<IIIIIBBQ',0,10010,2,3,4,0,0,77),
            read_world_finish=True,world_finish_body=finish_body(),tutorial_observer=events.append,
            before_finish_packets=((9905,b'bad'),))
        self.assertEqual(result['status'],'connection_processing_failed')
        self.assertEqual(events,[None])

    def test_tutorial_queue_is_bounded_before_world_finish(self):
        events=[]
        result,_=self.world_attempt(world_reserve_body=reserve_body(),
            world_start_body=struct.pack('<IIIIIBBQ',0,10010,2,3,4,0,0,77),
            read_world_finish=True,world_finish_body=finish_body(),tutorial_observer=events.append,
            before_finish_packets=tuple((9905,bytes(3)) for _ in range(65)))
        self.assertEqual(result['status'],'connection_processing_failed')
        self.assertEqual(result['tutorial_notifications_decoded'],64)
        self.assertEqual(events,[None])

    def test_world_refusals_survive_connection_cleanup(self):
        result,captures=self.world_attempt(world_reserve_body=reserve_body(16))
        self.assertEqual(captures,[(1,0),(3,1),(101,2),(109,3)])
        self.assertEqual(result['world_reserve_result_code'],16)
        self.assertEqual(result['world_entry_error'],'reserve_result_rejected')
        self.assertTrue(result['character_select_result_received'])
        self.assertTrue(result['selection_body_fully_decoded'])
        self.assertFalse(result['world_start_queued'])
        result,_=self.world_attempt(world_reserve_body=reserve_body(),
            world_start_body=struct.pack('<IIIIIBBQ',16,0,0,0,0,0,0,0))
        self.assertEqual(result['world_start_result_code'],16)
        self.assertEqual(result['world_entry_error'],'start_result_rejected')

    def test_missing_world_reserve_or_start_times_out_and_closes(self):
        for kwargs in ({},{'world_reserve_body':reserve_body()}):
            result,_=self.world_attempt(**kwargs)
            self.assertEqual(result['world_entry_error'],'world_entry_timeout')
            self.assertFalse(result['game_session_ready'])

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

    def test_blocked_info_stops_before_list_and_does_not_claim_ip_cause(self):
        body = struct.pack('<I', 59) + bytes.fromhex(FIXTURE['login_result_hex'])[4:]
        result, captures = self.attempt(login_body=body, read_character_list=True)
        self.assertEqual(captures, [(1, 0), (3, 1)])
        self.assertEqual(result['login_result_code'], 59)
        self.assertEqual(result['character_entry_state'], 'login_rejected')
        self.assertEqual(result['login_result_key'], 'BlockedInfo')
        self.assertEqual(result['login_error_message'], 'Доступ к игровому сервису ограничен сервером.')
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
            self.assertEqual(result['character_entry_state'], 'empty_list' if not keys else 'characters_available')

    def test_accepted_empty_list_is_distinct_from_login_refusal(self):
        result, captures = self.attempt(login_body=bytes.fromhex(FIXTURE['login_result_hex']),
            read_character_list=True, character_body=list_body(keys=()))
        self.assertEqual(captures, [(1, 0), (3, 1), (101, 2)])
        self.assertEqual(result['character_entry_state'], 'empty_list')
        self.assertEqual(result['character_list_result_code'], 0)
        self.assertEqual(result['character_count'], 0)
        self.assertIsNone(result['preferred_character_index'])
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


    def test_selection_reply_after_large_notification_burst_is_not_lost(self):
        result,captures=self.attempt(login_body=bytes.fromhex(FIXTURE['login_result_hex']),
            read_character_list=True,character_body=list_body(),character_index=0,
            wait_for_select=True,other_packets=(602,602,1781)+tuple([120]*80),
            select_body=bytes.fromhex(SELECTION_FIXTURE['select_result_hex']))
        self.assertEqual(captures,[(1,0),(3,1),(101,2),(109,3)])
        self.assertEqual(result['status'],'character_select_result')
        self.assertEqual(result['character_select_result_code'],0)
        self.assertEqual(result['other_packet_count'],83)
        self.assertEqual(result['other_packet_counts'],{'120':80,'602':2,'1781':1})
        self.assertEqual(len(result['other_packet_ids']),32)
        self.assertTrue(result['other_packet_sample_truncated'])

    def test_unbounded_notifications_stop_at_an_explicit_processing_budget(self):
        result,captures=self.attempt(login_body=bytes.fromhex(FIXTURE['login_result_hex']),
            read_character_list=True,character_body=list_body(),character_index=0,
            wait_for_select=True,other_packets=tuple([120]*4097))
        self.assertEqual(captures,[(1,0),(3,1),(101,2),(109,3)])
        self.assertEqual(result['status'],'other_packet_budget_exceeded')
        self.assertEqual(result['other_packet_count'],4097)
        self.assertEqual(result['other_packet_counts'],{'120':4096})
        self.assertFalse(result['character_select_result_received'])


if __name__ == '__main__': unittest.main()
