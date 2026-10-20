"""Bounded native receive stream: raw transport -> inner frames -> packet bodies.

Evidence: HEADLESS-TRANSPORT-STAGE / BLOCK-DECODE / LISTENER-LOOP /
RECEIVE-B. Limits and terminal error policy are local client decisions.
No sockets, packet factory, automatic key changes, CRC or auth are inferred.
"""
from dataclasses import dataclass, field

from .transport_header import inspect_transport_header, take_transport_frame
from .receive_frame import take_receive_b_frame


@dataclass(frozen=True, slots=True)
class ReceiveLimits:
    max_transport_size: int
    max_block_output: int
    max_inner_size: int
    max_raw_buffer: int
    max_decoded_buffer: int

    def __post_init__(self):
        for value, lo, hi in ((self.max_transport_size, 3, 0x7fffff),
                              (self.max_block_output, 1, 0x100000),
                              (self.max_inner_size, 5, 0xffffff),
                              (self.max_raw_buffer, self.max_transport_size, 0x1000000),
                              (self.max_decoded_buffer, self.max_inner_size, 0x2000000)):
            if type(value) is not int or not lo <= value <= hi:
                raise ValueError('Invalid receive stream resource limit')


@dataclass(frozen=True, slots=True)
class IncomingPacket:
    packet_id: int
    body: bytes = field(repr=False)


class ReceiveStream:
    """Single connection, single owner, with a key supplied for EACH packet.

    feed() accepts bounded socket chunks. next_packet() returns at most one
    packet and expands at most max_transport_frames blocks per call. None can
    mean incomplete input or exhausted work budget; schedule another bounded
    call while complete buffered transport frames remain. Do not read more from
    the socket when feed capacity is exhausted. A local/protocol failure closes
    the stream; it is never resynchronized by skipping arbitrary bytes.
    uncompressed_offset is explicit: native lobby A=0, game B=3. Compressed
    blocks always decode their bytes after the three-byte transport header.
    """
    def __init__(self, limits: ReceiveLimits, *, uncompressed_offset: int = 3):
        if not isinstance(limits, ReceiveLimits):
            raise TypeError('Expected receive limits')
        if type(uncompressed_offset) is not int or uncompressed_offset not in (0, 3):
            raise ValueError('Expected native uncompressed offset 0 or 3')
        self._uncompressed_offset = uncompressed_offset
        self._limits = limits
        self._raw = bytearray()
        self._decoded = bytearray()
        self._eof = False
        self._closed = False
        self._error = None

    def __repr__(self):
        return f'ReceiveStream(raw_bytes={self.raw_bytes}, decoded_bytes={self.decoded_bytes}, closed={self.closed})'

    @property
    def raw_bytes(self): return len(self._raw)

    @property
    def decoded_bytes(self): return len(self._decoded)

    @property
    def input_capacity(self):
        return 0 if self._closed or self._eof else self._limits.max_raw_buffer - len(self._raw)

    @property
    def closed(self): return self._closed

    @property
    def error(self): return self._error

    @property
    def finished(self): return self._eof and not self._raw and not self._decoded and not self._closed

    def _active(self):
        if self._closed:
            raise RuntimeError('Receive stream is closed')

    def close(self):
        self._closed = True
        self._raw.clear()
        self._decoded.clear()

    def _fail(self, reason):
        self._error = reason
        self.close()
        raise ValueError('Receive stream failed: ' + reason) from None

    def feed(self, chunk: bytes):
        self._active()
        if self._eof:
            raise RuntimeError('Receive input has ended')
        if type(chunk) is not bytes:
            raise TypeError('Expected immutable socket bytes')
        if len(chunk) > self.input_capacity:
            # No bytes consumed: the owner can drain and offer the same chunk.
            raise BufferError('Receive input buffer limit reached')
        self._raw.extend(chunk)

    def end_input(self):
        """Mark socket EOF; buffered complete packets must still be drained."""
        self._active()
        self._eof = True

    def next_packet(self, *, key_bits: int, max_transport_frames: int):
        self._active()
        if type(key_bits) is not int or not 0 <= key_bits <= 0xffffffffffffffff:
            raise ValueError('Expected uint64 receive key')
        if type(max_transport_frames) is not int or max_transport_frames < 1:
            raise ValueError('Expected positive transport work budget')
        expanded = 0
        while True:
            try:
                inner = take_receive_b_frame(self._decoded, key_bits, max_frame_size=self._limits.max_inner_size)
            except ValueError:
                self._fail('invalid_inner_frame')
            if inner is not None:
                plain, consumed = inner
                del self._decoded[:consumed]
                return IncomingPacket(int.from_bytes(plain[3:5], 'little'), plain[5:])
            # Validate the inner header as soon as it is present (the native
            # size probe waits for five bytes). This avoids retaining a known
            # impossible declared length while waiting for more socket input.
            if len(self._decoded) >= 3:
                size = int.from_bytes(self._decoded[:3], 'little')
                if not 5 <= size <= self._limits.max_inner_size:
                    self._fail('invalid_inner_frame')
            if expanded == max_transport_frames:
                return None
            try:
                header = inspect_transport_header(self._raw, max_frame_size=self._limits.max_transport_size)
            except ValueError:
                self._fail('invalid_transport_frame')
            if header is None or len(self._raw) < header.total_size:
                if self._eof and (self._raw or self._decoded):
                    self._fail('truncated_input')
                return None
            try:
                body, consumed = take_transport_frame(self._raw,
                    max_frame_size=self._limits.max_transport_size, max_output_size=self._limits.max_block_output,
                    uncompressed_offset=self._uncompressed_offset)
            except ValueError:
                self._fail('invalid_transport_block')
            if len(self._decoded) + len(body) > self._limits.max_decoded_buffer:
                self._fail('decoded_buffer_limit')
            del self._raw[:consumed]
            self._decoded.extend(body)
            expanded += 1
