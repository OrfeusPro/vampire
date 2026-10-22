"""Bounded nonblocking outbound pump; connection/auth/lifecycle are separate.

Native partial-send evidence and local zero-send policy: HEADLESS-SEND-DRAIN.md.
"""
from dataclasses import dataclass
from .outbound import OutboundFrames


@dataclass(frozen=True, slots=True)
class SendProgress:
    bytes_sent: int
    blocked: bool


def drain_outbound(sock, queue: OutboundFrames, *, max_send_calls: int,
                   on_frame_sent=None) -> SendProgress:
    """Send bounded work on an already connected nonblocking socket.

    Caller owns readiness scheduling and failures. Blocking/interrupt leaves the
    unsent tail queued. OSError propagates; no reconnect or automatic replay.
    Zero progress raises ConnectionError (stricter than observed native route).
    on_frame_sent receives the original immutable frame once all its bytes have
    been accepted by send(); this does not prove peer receipt or processing.
    """
    if isinstance(max_send_calls, bool) or not isinstance(max_send_calls, int) or max_send_calls < 1:
        raise ValueError('Expected a positive socket-call budget')
    if on_frame_sent is not None and not callable(on_frame_sent):
        raise TypeError('Expected frame completion handler')
    sent = 0
    for _ in range(max_send_calls):
        pending = queue.peek_frame()
        if pending is None:
            break
        try:
            count = sock.send(pending)
        except (BlockingIOError, InterruptedError):
            return SendProgress(sent, True)
        if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= len(pending):
            raise RuntimeError('Socket returned an invalid send count')
        if count == 0:
            raise ConnectionError('Socket made no send progress')
        completed = queue.consume_sent(count)
        sent += count
        if completed is not None and on_frame_sent is not None:
            on_frame_sent(completed)
    return SendProgress(sent, False)
