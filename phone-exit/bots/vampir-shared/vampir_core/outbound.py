"""Bounded immutable outbound frames for one future session owner.

No sockets or concurrency: use from a single event-loop/session owner. Evidence
and local differences from native error behavior: HEADLESS-SEND-B.md.
"""
from collections import deque
from .ping import PingPayload
from .key_change import KeyChangePayload
from .send_frame import (encode_ping_frame_b, encode_key_changed_frame_b,
                         encode_character_list_frame_b, encode_character_select_frame_b)
from .character_select import CharacterSelectPayload
from .send_frame import encode_version_frame_b, encode_login_frame_b


class OutboundFrames:
    def __init__(self, *, key_bits: int, sequence: int, max_queued_bytes: int, max_queued_frames: int):
        for name, value, minimum, maximum in [
                ('key', key_bits, 0, (1 << 64)-1), ('sequence', sequence, 0, 65535),
                ('byte budget', max_queued_bytes, 1, None), ('frame budget', max_queued_frames, 1, None)]:
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum or (maximum is not None and value > maximum):
                raise ValueError('Invalid outbound '+name)
        self._key_bits = key_bits
        self._sequence = sequence
        self._max_bytes = max_queued_bytes
        self._max_frames = max_queued_frames
        self._frames: deque[bytes] = deque()
        self._queued_bytes = 0
        self._head_offset = 0
        self._closed = False

    def __repr__(self):
        return f'OutboundFrames(frames={self.queued_frames}, bytes={self.queued_bytes}, key=<redacted>)'

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def queued_bytes(self) -> int:
        return self._queued_bytes

    @property
    def queued_frames(self) -> int:
        return len(self._frames)

    def _append(self, frame: bytes) -> bytes:
        if self._closed:
            raise RuntimeError('Outbound connection is closed')
        if len(self._frames) >= self._max_frames or self._queued_bytes + len(frame) > self._max_bytes:
            raise BufferError('Outbound frame queue limit reached')
        self._frames.append(frame)
        self._queued_bytes += len(frame)
        self._sequence = (self._sequence + 1) & 65535
        return frame

    def queue_ping(self, payload: PingPayload) -> bytes:
        return self._append(encode_ping_frame_b(payload, self._sequence, self._key_bits))

    def queue_character_list(self) -> bytes:
        return self._append(encode_character_list_frame_b(self._sequence, self._key_bits))

    def queue_version(self, payload, *, max_payload_size):
        return self._append(encode_version_frame_b(payload, self._sequence, self._key_bits,
                                                  max_payload_size=max_payload_size))

    def queue_login(self, payload, *, max_payload_size):
        return self._append(encode_login_frame_b(payload, self._sequence, self._key_bits,
                                                max_payload_size=max_payload_size))

    def queue_character_select(self, payload: CharacterSelectPayload) -> bytes:
        return self._append(encode_character_select_frame_b(payload, self._sequence, self._key_bits))

    def close(self) -> None:
        """Invalidate the connection queue, including every unsent partial tail."""
        self._closed = True
        self._frames.clear()
        self._queued_bytes = 0
        self._head_offset = 0

    def acknowledge_key_change(self, payload: KeyChangePayload) -> bytes:
        """Queue ack under old key, then switch. Failure leaves state unchanged.

        Native handler updates even if send returns false; this stricter local
        policy must surface BufferError to the session owner (no silent retry).
        """
        frame = self._append(encode_key_changed_frame_b(payload, self._sequence, self._key_bits))
        self._key_bits = payload.key_bits
        return frame

    def pop_frame(self) -> bytes | None:
        """Transfer one immutable frame to its sender; empty queue returns None."""
        if not self._frames:
            return None
        frame = self._frames.popleft()
        remaining = len(frame) - self._head_offset
        if self._head_offset:
            frame = frame[self._head_offset:]
        self._head_offset = 0
        self._queued_bytes -= remaining
        return frame

    def peek_frame(self) -> memoryview | None:
        """Read-only view of unsent head bytes; it remains owned by the queue."""
        if not self._frames:
            return None
        return memoryview(self._frames[0])[self._head_offset:]

    def consume_sent(self, count: int) -> None:
        """Commit only bytes accepted by the socket, never discard an unsent tail."""
        available = len(self._frames[0]) - self._head_offset if self._frames else 0
        if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= available:
            raise ValueError('Sent count outside pending head frame')
        self._head_offset += count
        self._queued_bytes -= count
        if self._frames and count == available:
            self._frames.popleft()
            self._head_offset = 0
