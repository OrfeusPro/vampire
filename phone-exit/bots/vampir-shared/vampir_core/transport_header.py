"""First receive-stage header inspection; distinct from receive_frame.py's second stage.

Evidence: HEADLESS-TRANSPORT-STAGE.md and HEADLESS-BLOCK-DECODE.md.
No complete socket/packet transport is provided.
"""
from dataclasses import dataclass
from .block_decode import decode_transport_block


@dataclass(frozen=True, slots=True)
class TransportHeader:
    total_size: int
    compressed: bool


def inspect_transport_header(buffer: bytes, *, max_frame_size: int) -> TransportHeader | None:
    """Read size23/flag from3 bytes; reject zero/undersize frames by local policy."""
    if isinstance(max_frame_size, bool) or not isinstance(max_frame_size, int) or not 3 <= max_frame_size <= 0x7fffff:
        raise ValueError('Expected explicit transport limit between3 and8388607')
    if len(buffer) < 3:
        return None
    raw = int.from_bytes(buffer[:3], 'little')
    total_size = raw & 0x7fffff
    if not 3 <= total_size <= max_frame_size:
        raise ValueError('Transport frame size outside local bounds')
    return TransportHeader(total_size, bool(raw & 0x800000))


def take_uncompressed_transport_frame(buffer: bytes, *, max_frame_size: int) -> tuple[bytes, int] | None:
    """Return body/consumed for one complete uncompressed frame, without mutation.

    Raises for compressed input once complete; never silently treats it as raw.
    This implements the investigated skip=3 branch only.
    """
    header = inspect_transport_header(buffer, max_frame_size=max_frame_size)
    if header is None or len(buffer) < header.total_size:
        return None
    if header.compressed:
        raise NotImplementedError('Compressed transport decoding has not been implemented')
    return bytes(buffer[3:header.total_size]), header.total_size


def take_transport_frame(buffer: bytes, *, max_frame_size: int,
                         max_output_size: int) -> tuple[bytes, int] | None:
    """Extract one skip=3 transport body, decoding compressed blocks if needed.

    Explicit input/output limits bound memory; extra frames remain unconsumed.
    Empty compressed output is rejected as in the investigated native stage.
    """
    if (isinstance(max_output_size, bool) or not isinstance(max_output_size, int)
            or not 1 <= max_output_size <= 0x100000):
        raise ValueError('Expected an output limit between 1 and 1048576')
    header = inspect_transport_header(buffer, max_frame_size=max_frame_size)
    if header is None or len(buffer) < header.total_size:
        return None
    if not header.compressed and header.total_size - 3 > max_output_size:
        raise ValueError('Transport body exceeds output limit')
    body = bytes(buffer[3:header.total_size])
    if header.compressed:
        body = decode_transport_block(body, max_output_size=max_output_size)
        if not body:
            raise ValueError('Empty compressed transport output')
    return body, header.total_size
