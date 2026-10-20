"""Bounded Version -> result -> explicit LobbyLogin, no list/game/retry IO."""
from dataclasses import dataclass, field
import math
import select
import time

from .lobby_packets import LobbyVersionPayload, LobbyLoginPayload, decode_lobby_version_result
from .lobby_login_result import decode_lobby_login_result
from .receive_stream import ReceiveLimits, ReceiveStream
from .send_frame import encode_lobby_version_frame, encode_lobby_login_frame


@dataclass(frozen=True, slots=True)
class LobbyLoginProbeResult:
    summary: dict
    response: object = field(default=None, repr=False)


def exchange_lobby_login(sock, version, login, *, timeout=15):
    if not isinstance(version, LobbyVersionPayload) or not isinstance(login, LobbyLoginPayload):
        raise TypeError('Expected separate explicit lobby Version/Login')
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError('Invalid lobby probe timeout')
    receiver = ReceiveStream(ReceiveLimits(65536, 65536, 65536, 131072, 131072), uncompressed_offset=0)
    sent = received = 0
    ids = []
    version_code = None
    login_sent = False
    stage = 'version'
    pending = b''
    last_body_size = None

    def result(status, response=None, error=None):
        summary = dict(status=status, stage=stage, bytes_sent=sent, bytes_received=received,
            packet_ids=ids.copy(), version_result_code=version_code, login_sent=login_sent,
            login_result_received=response is not None,
            login_result_code=response.result_code if response is not None else None,
            last_body_size=last_body_size,
            server_list_sent=False, game_session_ready=False)
        if error: summary['error_type'] = type(error).__name__
        return LobbyLoginProbeResult(summary, response)

    try:
        pending = encode_lobby_version_frame(version, 0, max_payload_size=32768)
        sock.setblocking(False)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if pending:
                try:
                    n = sock.send(pending)
                    if n == 0: raise ConnectionError('Lobby socket send returned zero')
                    pending = pending[n:]
                    sent += n
                    if stage == 'login': login_sent = True
                except (BlockingIOError, InterruptedError): pass
            for _ in range(8):
                packet = receiver.next_packet(key_bits=0, max_transport_frames=4)
                if packet is None: break
                ids.append(packet.packet_id)
                last_body_size = len(packet.body)
                if len(ids) > 32: return result('packet_budget_exceeded')
                if packet.packet_id == 2:
                    if stage != 'version' or pending: return result('unexpected_version_result')
                    response = decode_lobby_version_result(packet.body)
                    version_code = response.result_code
                    if version_code != 0: return result('version_rejected')
                    if response.flag_14: return result('additional_numeric_context_required')
                    pending = encode_lobby_login_frame(login, 1, max_payload_size=32768)
                    stage = 'login'
                    break
                if packet.packet_id == 4:
                    if stage != 'login' or not login_sent or pending: return result('unexpected_login_result')
                    response = decode_lobby_login_result(packet.body, max_payload_size=65536)
                    return result('lobby_login_result', response)
            if receiver.input_capacity == 0: return result('receive_budget_exceeded')
            try:
                data = sock.recv(min(16384, receiver.input_capacity))
                if not data: return result('server_closed')
                received += len(data)
                if received > 262144: return result('receive_budget_exceeded')
                receiver.feed(data)
            except (BlockingIOError, InterruptedError):
                select.select([sock], [sock] if pending else [], [], min(0.05, max(0, deadline - time.monotonic())))
        return result('timeout')
    except (ValueError, BufferError, OSError) as exc:
        return result('transport_error' if isinstance(exc, OSError) else 'protocol_error', error=exc)
    finally:
        pending = b''
        receiver.close()
        sock.close()
