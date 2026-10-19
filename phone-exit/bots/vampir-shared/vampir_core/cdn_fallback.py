"""Offline CDN fallback envelope decoder; optional crypto backend on demand.

Evidence: HEADLESS-CDN-FALLBACK.md. The public seed is compiled client data,
not an account credential. Native orchestration/arguments were replayed with
crypto backend shims; the native AES/SHA core was not executed. No network or
JSON acceptance. The Android backend is still unverified.
"""
from hashlib import sha256

from .cdn_response import MAX_BODY_BYTES

_KEY = sha256(b'netmarble_neo_vam_1234567890').digest()


def decrypt_cdn_fallback(payload: bytes) -> bytes:
    """Decode IV16 + AES-256-CBC ciphertext with PKCS7 padding.

    Local policy requires at least one ciphertext block and at most 2 MiB for
    the whole envelope. Invalid size/padding raises ValueError; the native
    helper instead returns an empty string on crypto failure. A legitimately
    empty plaintext returns b''. Output is raw bytes, without NUL truncation,
    Unicode/JSON conversion or configuration application.
    """
    if (not isinstance(payload, bytes) or not 32 <= len(payload) <= MAX_BODY_BYTES
            or (len(payload) - 16) % 16):
        raise ValueError('Invalid CDN fallback envelope')
    try:
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        raise RuntimeError('CDN fallback decoding requires the optional cryptography backend') from None
    try:
        decryptor = Cipher(algorithms.AES(_KEY), modes.CBC(payload[:16])).decryptor()
        padded = decryptor.update(payload[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except (ValueError, UnsupportedAlgorithm):
        raise ValueError('Invalid CDN fallback ciphertext') from None
