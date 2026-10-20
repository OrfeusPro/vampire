"""Verified frame helper algorithms, not a complete transport or frame decoder.

Evidence: resource-tools/vampir/knowledge/evidence/network/HEADLESS-FRAME-PRIMITIVES.md.
CRC state initialization and XOR fallback match the investigated client build.
Session key acquisition, receive validation and frame boundaries remain unknown.
"""
import zlib
from .ping import SOURCE_SHA256

FALLBACK_XOR_KEY = 0x9ab378c9d02084a7


def payload_crc32(payload: bytes) -> int:
    """Standard CRC32 with the client's initial state/final complement."""
    return zlib.crc32(payload) & 0xffffffff


def xor_transform(payload: bytes, key_bits: int = 0) -> bytes:
    """Repeat the little-endian key; zero selects the native fallback key."""
    if isinstance(key_bits, bool) or not isinstance(key_bits, int) or not 0 <= key_bits < 1 << 64:
        raise ValueError('Expected unsigned 64-bit key pattern')
    key = (key_bits or FALLBACK_XOR_KEY).to_bytes(8, 'little')
    return bytes(value ^ key[index & 7] for index, value in enumerate(payload))
