"""Offline NID storage suffix for the source-verified aligned ASCII subset."""


def derive_nid_storage_suffix(*, subject: str, nm_device_key: str) -> str:
    """Derive suffix only; does not validate tokens, select a profile or read files.

    Local policy: printable ASCII subject, 32..1024 bytes aligned to 16, and
    exactly 32 ASCII hex key characters. The key's case is significant and is
    preserved. Existing stored identities must never be normalized silently.
    Native caller accepts a broader input domain; that domain is not modeled.
    """
    if not isinstance(subject, str) or not 32 <= len(subject) <= 1024 or len(subject) % 16:
        raise ValueError('Unsupported NID subject length')
    if any(not 32 <= ord(c) <= 126 for c in subject):
        raise ValueError('Unsupported NID subject encoding')
    if not isinstance(nm_device_key, str) or len(nm_device_key) != 32 or any(
            c not in '0123456789abcdefABCDEF' for c in nm_device_key):
        raise ValueError('Unsupported NM device key format')
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        raise RuntimeError('Optional cryptography backend is required for NID storage suffix') from None
    value = bytes(ord(c) - 1 for c in subject)
    encryptor = Cipher(algorithms.AES(nm_device_key.encode('ascii')), modes.ECB()).encryptor()
    return (encryptor.update(value) + encryptor.finalize()).hex().upper()
