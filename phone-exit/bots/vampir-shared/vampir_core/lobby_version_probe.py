"""One bounded lobby Version exchange, without Login, retry or server-list IO."""
import math
import select
import time

from .lobby_packets import LobbyVersionPayload, decode_lobby_version_result
from .receive_stream import ReceiveLimits, ReceiveStream
from .send_frame import encode_lobby_version_frame


def exchange_lobby_version(sock, payload, *, timeout=10):
    if not isinstance(payload, LobbyVersionPayload): raise TypeError('Expected separate lobby Version')
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError('Invalid lobby probe timeout')
    receiver = ReceiveStream(ReceiveLimits(65536, 65536, 65536, 131072, 131072), uncompressed_offset=0)
    ids = []
    sent = received = 0
    pending = b''
    last_body_size = None

    def result(status, response=None):
        return dict(status=status, target_role='cdn_lobby', bytes_sent=sent, bytes_received=received,
            packet_ids=ids.copy(), lobby_version_result_received=response is not None,
            result_code=response.result_code if response is not None else None,
            flag_14=response.flag_14 if response is not None else None,
            last_body_size=last_body_size,
            login_sent=False, server_list_sent=False, game_session_ready=False)

    try:
        pending = encode_lobby_version_frame(payload, 0, max_payload_size=32768)
        sock.setblocking(False)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if pending:
                try:
                    n = sock.send(pending)
                    if n == 0: raise ConnectionError('Lobby socket send returned zero')
                    pending = pending[n:]
                    sent += n
                except (BlockingIOError, InterruptedError): pass
            for _ in range(8):
                packet = receiver.next_packet(key_bits=0, max_transport_frames=4)
                if packet is None: break
                ids.append(packet.packet_id)
                last_body_size = len(packet.body)
                if len(ids) > 32: return result('packet_budget_exceeded')
                if packet.packet_id == 2:
                    response = decode_lobby_version_result(packet.body)
                    if pending: return result('outbound_pending_at_result')
                    return result('lobby_version_result', response)
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
        summary = result('transport_error' if isinstance(exc, OSError) else 'protocol_error')
        summary['error_type'] = type(exc).__name__
        return summary
    finally:
        pending = b''
        receiver.close()
        sock.close()
