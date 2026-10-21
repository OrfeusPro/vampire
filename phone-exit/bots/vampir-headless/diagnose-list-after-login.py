"""Explicit diagnostic: ask for one list even after a rejected Game Login.

Not a runtime authentication policy. Uses fresh caller-provided fields and one
socket; never selects a character, retries, or treats a rejected login as ready.
"""
import select
import time

from vampir_core.outbound import OutboundFrames
from vampir_core.receive_stream import ReceiveStream, ReceiveLimits
from vampir_core.socket_send import drain_outbound
from vampir_core.version_result import decode_version_result
from vampir_core.login_result import decode_login_result
from vampir_core.character_list import decode_character_list
from vampir_core.key_change import KeyChangePayload


def exchange(sock, version, login, *, timeout=10, read_character_list=False, ping_clock=None):
    if read_character_list is not True or type(timeout) not in (int, float) or not 0 < timeout <= 10:
        raise ValueError('Explicit bounded diagnostic list operation required')
    receiver = ReceiveStream(ReceiveLimits(1048576, 1048576, 1048576, 2097152, 2097152))
    outbound = OutboundFrames(key_bits=0, sequence=0, max_queued_bytes=65536, max_queued_frames=8)
    key = 0
    stage = 'version'
    report = dict(diagnostic_list_after_login=True, version_result_code=None,
        login_result_code=None, character_list_queued=False, character_list_received=False,
        character_list_result_code=None, character_count=None, initial_ping_queued=False,
        bytes_sent=0, bytes_received=0, packet_ids=[], game_session_ready=False,
        character_select_sent=False)
    try:
        sock.setblocking(False)
        outbound.queue_version(version, max_payload_size=1048576)
        if ping_clock is not None:
            outbound.queue_ping(ping_clock.initial_ping(utc_millis=time.time_ns() // 1000000))
            report['initial_ping_queued'] = True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            report['bytes_sent'] += drain_outbound(sock, outbound, max_send_calls=8).bytes_sent
            for _ in range(32):
                packet = receiver.next_packet(key_bits=key, max_transport_frames=8)
                if packet is None: break
                report['packet_ids'].append(packet.packet_id)
                if len(report['packet_ids']) > 64: return dict(report, status='packet_budget_exceeded')
                if packet.packet_id == 11:
                    change = KeyChangePayload.decode(packet.body)
                    outbound.acknowledge_key_change(change)
                    key = change.key_bits
                elif packet.packet_id == 2:
                    if stage != 'version': return dict(report, status='unexpected_version')
                    code = decode_version_result(packet.body).result_code
                    report['version_result_code'] = code
                    if code: return dict(report, status='version_rejected')
                    outbound.queue_login(login, max_payload_size=1048576)
                    stage = 'login'
                elif packet.packet_id == 4:
                    if stage != 'login': return dict(report, status='unexpected_login')
                    report['login_result_code'] = decode_login_result(packet.body, max_payload_size=1048576).result_code
                    outbound.queue_character_list()
                    report['character_list_queued'] = True
                    # Flush before observing any already buffered EOF: record actual
                    # send completion separately from queueing the request.
                    report['bytes_sent'] += drain_outbound(sock, outbound, max_send_calls=8).bytes_sent
                    report['character_list_sent'] = outbound.queued_bytes == 0
                    stage = 'list'
                    deadline = time.monotonic() + timeout
                elif packet.packet_id == 102:
                    if stage != 'list': return dict(report, status='unexpected_list')
                    result = decode_character_list(packet.body, max_payload_size=1048576,
                        max_characters=64, max_extension_items=4096)
                    report.update(character_list_received=True, character_list_result_code=result.result_code,
                        character_count=len(result.records))
                    return dict(report, status='character_list_result')
            if receiver.finished: return dict(report, status='server_closed')
            if not receiver.input_capacity: return dict(report, status='receive_budget_exceeded')
            readable, _, _ = select.select([sock], [sock] if outbound.queued_bytes else [], [], 0.05)
            if readable:
                data = sock.recv(min(16384, receiver.input_capacity))
                if not data:
                    receiver.end_input()
                else:
                    report['bytes_received'] += len(data)
                    if report['bytes_received'] > 2097152: return dict(report, status='receive_budget_exceeded')
                    receiver.feed(data)
        return dict(report, status='timeout')
    except (OSError, ValueError, BufferError, RuntimeError) as error:
        return dict(report, status='diagnostic_error', error_type=type(error).__name__)
    finally:
        receiver.close()
        outbound.close()
        sock.close()
