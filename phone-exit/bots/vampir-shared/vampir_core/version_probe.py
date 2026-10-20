"""Bounded first-Version exchange; never sends Login or character requests."""
import math
import select
import time

from .key_change import KeyChangePayload
from .outbound import OutboundFrames
from .receive_stream import ReceiveLimits, ReceiveStream
from .socket_send import drain_outbound
from .version_packet import VersionPayload
from .version_result import decode_version_result


def exchange_version(sock, payload, *, timeout=10):
    """Own one connected socket through close, using native connected key/seq 0.

    No auth token, heartbeat, retry, unknown-packet response or Login transition.
    Resource/time budgets here are local policies, not claimed server limits.
    """
    if not isinstance(payload, VersionPayload): raise TypeError('Expected Version payload')
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError('Version probe timeout must be in (0,30]')
    outbound = OutboundFrames(key_bits=0, sequence=0, max_queued_bytes=65536, max_queued_frames=8)
    receiver = ReceiveStream(ReceiveLimits(65536, 65536, 65536, 131072, 131072))
    key = 0
    ids = []
    changes = 0
    sent = received = 0
    def result(reason, code=None):
        return dict(status=reason, version_result_received=code is not None,
            version_result_code=code, packet_ids=ids.copy(), key_notifications=changes,
            bytes_sent=sent, bytes_received=received, login_sent=False, game_session_ready=False)
    try:
        outbound.queue_version(payload, max_payload_size=32768)
        sock.setblocking(False)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sent += drain_outbound(sock, outbound, max_send_calls=8).bytes_sent
            for _ in range(8):
                packet = receiver.next_packet(key_bits=key, max_transport_frames=4)
                if packet is None: break
                ids.append(packet.packet_id)
                if len(ids) > 32: return result('packet_budget_exceeded')
                if packet.packet_id == 11:
                    changes += 1
                    if changes > 4: return result('key_notification_budget_exceeded')
                    notification = KeyChangePayload.decode(packet.body)
                    outbound.acknowledge_key_change(notification)
                    key = notification.key_bits
                    sent += drain_outbound(sock, outbound, max_send_calls=8).bytes_sent
                elif packet.packet_id == 2:
                    decoded = decode_version_result(packet.body)
                    if outbound.queued_bytes: return result('outbound_pending_at_result')
                    return result('version_result', decoded.result_code)
            if receiver.input_capacity == 0: return result('receive_budget_exceeded')
            try:
                data = sock.recv(min(16384, receiver.input_capacity))
                if not data: return result('server_closed')
                received += len(data)
                if received > 262144: return result('receive_budget_exceeded')
                receiver.feed(data)
            except (BlockingIOError, InterruptedError):
                remaining = max(0, deadline - time.monotonic())
                select.select([sock], [sock] if outbound.queued_bytes else [], [], min(0.05, remaining))
        return result('timeout')
    finally:
        outbound.close()
        receiver.close()
        key = 0
        sock.close()
