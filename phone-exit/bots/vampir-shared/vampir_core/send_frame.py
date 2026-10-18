"""Selected offline frame assembly for the investigated send-A/send-B paths.

Evidence: HEADLESS-SEND-FRAME.md and HEADLESS-SEND-B.md. No socket/login.
"""
import struct
from .ping import PingPayload, SOURCE_SHA256
from .frame_primitives import payload_crc32, xor_transform
from .key_change import KeyChangePayload, KEY_CHANGED_ID


def _encode(packet_id: int, body: bytes, sequence: int, key_bits: int) -> bytes:
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence <= 65535:
        raise ValueError('Expected unsigned 16-bit sequence')
    inner = struct.pack('<HH', packet_id, sequence) + body
    total_size = 3 + 4 + len(inner)
    return total_size.to_bytes(3, 'little') + xor_transform(struct.pack('<I', payload_crc32(inner)) + inner, key_bits)


def encode_ping_frame(payload: PingPayload, sequence: int) -> bytes:
    """Build the native send-A Ping frame; caller owns the per-connection sequence."""
    if not isinstance(payload, PingPayload):
        raise TypeError('Expected PingPayload')
    return _encode(16, payload.encode(), sequence, 0)


def encode_ping_frame_b(payload: PingPayload, sequence: int, key_bits: int) -> bytes:
    """Build keyed send-B Ping; caller owns the per-connection sequence/key."""
    if not isinstance(payload, PingPayload):
        raise TypeError('Expected PingPayload')
    return _encode(16, payload.encode(), sequence, key_bits)


def encode_key_changed_frame_b(payload: KeyChangePayload, sequence: int, key_bits: int) -> bytes:
    """Build send-B ack carrying the new key, encrypted with the current key."""
    if not isinstance(payload, KeyChangePayload):
        raise TypeError('Expected KeyChangePayload')
    return _encode(KEY_CHANGED_ID, payload.encode(), sequence, key_bits)
