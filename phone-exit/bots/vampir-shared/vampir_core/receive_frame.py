"""Second-stage bounded size inspection, not a raw socket frame parser.

Evidence: HEADLESS-RECEIVE-ENVELOPE.md. The native probe is shared by two
receive implementations. Local rejection of declared sizes below5 and an
explicit application maximum are stricter than the investigated leaf routine.
Use transport_header.py for the preceding raw size23/compression-flag layer.
"""
from .frame_primitives import xor_transform


def peek_receive_frame_size(buffer: bytes, *, max_frame_size: int) -> int | None:
    """Return the complete frame size, None for incomplete input, raise on bad size.

    Caller must choose a memory limit; this module does not infer a server limit.
    No bytes are consumed or modified and no CRC or packet fields are interpreted.
    """
    if isinstance(max_frame_size, bool) or not isinstance(max_frame_size, int) or not 5 <= max_frame_size <= 0xffffff:
        raise ValueError('Expected explicit frame limit between5 and16777215')
    if len(buffer) < 5:
        return None
    declared = int.from_bytes(buffer[:3], 'little')
    if not 5 <= declared <= max_frame_size:
        raise ValueError('Declared frame size outside local bounds')
    return declared if len(buffer) >= declared else None


def take_receive_a_frame(buffer: bytes, *, max_frame_size: int) -> tuple[bytes, int] | None:
    """Extract and unwrap one complete receive-A frame, preserving its header.

    Evidence: HEADLESS-LISTENER-LOOP.md. Only receive-A's fallback XOR is used;
    the result remains an opaque internal frame, without integrity validation.
    Local size>=5 policy is stricter than the native probe. Input is unchanged.
    """
    size = peek_receive_frame_size(buffer, max_frame_size=max_frame_size)
    if size is None:
        return None
    return bytes(buffer[:3]) + xor_transform(buffer[3:size]), size


def take_receive_b_frame(buffer: bytes, key_bits: int, *, max_frame_size: int) -> tuple[bytes, int] | None:
    """Unwrap one receive-B frame with an explicit current peer key.

    Evidence: HEADLESS-RECEIVE-B.md. No CRC is added or inferred. The native
    bookkeeping notification keyed by packet ID belongs to the session layer,
    and is not performed here. Zero key uses the established fallback bits.
    """
    if isinstance(key_bits, bool) or not isinstance(key_bits, int) or not 0 <= key_bits <= 0xffffffffffffffff:
        raise ValueError('Expected unsigned 64-bit peer key bits')
    size = peek_receive_frame_size(buffer, max_frame_size=max_frame_size)
    if size is None:
        return None
    return bytes(buffer[:3]) + xor_transform(buffer[3:size], key_bits), size
