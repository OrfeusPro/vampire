"""One offline GMC2 secret chunk; optional cryptography backend loaded on demand.

Evidence: HEADLESS-SDK-OAEP.md. Windows backend verified; Android not verified.
No key acquisition, network, storage or full encSecretConstants list parsing.
"""
import base64

from .sdk_constants import decode_sdk_base64


def decrypt_sdk_secret_chunk(ciphertext: str, key_body: str) -> bytes:
    """Decrypt standard Base64 ciphertext with the supplied RSA private-key body.

    Local limits: 8192 ASCII key characters, RSA 2048/3072/4096 bits, one exact
    modulus-sized ciphertext. Return raw plaintext bytes, without JSON/UTF-8
    assumptions. Input key and plaintext are never included in errors.
    """
    encrypted = decode_sdk_base64(ciphertext)
    if not isinstance(key_body, str) or not 0 < len(key_body) <= 8192:
        raise ValueError('Invalid SDK secret key')
    try:
        body = key_body.encode('ascii')
        # Accept only a compact canonical body, no nested PEM or whitespace.
        key_der = base64.b64decode(body, validate=True)
        if base64.b64encode(key_der) != body:
            raise ValueError
    except ValueError:
        raise ValueError('Invalid SDK secret key') from None
    try:
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError:
        raise RuntimeError('SDK secret decoding requires the optional cryptography backend') from None
    pem = b'-----BEGIN RSA PRIVATE KEY-----\n'+body+b'\n-----END RSA PRIVATE KEY-----'
    try:
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size not in (2048, 3072, 4096):
            raise ValueError
        if len(encrypted) != key.key_size//8:
            raise ValueError
        return key.decrypt(encrypted, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                  algorithm=hashes.SHA256(), label=None))
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ValueError('Invalid SDK secret key or ciphertext') from None
