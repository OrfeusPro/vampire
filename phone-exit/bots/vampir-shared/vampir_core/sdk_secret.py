"""Offline GMC2 secret chunks/list; optional crypto backend loaded on demand.

Evidence: HEADLESS-SDK-OAEP.md. Windows backend verified; Android not verified.
No key acquisition, network, storage or endpoint binding validation.
"""
import base64
import json
import math

from .sdk_constants import decode_sdk_base64


def decrypt_sdk_secret_chunk(ciphertext: str, key_body: str) -> bytes:
    """Decrypt standard Base64 ciphertext with the supplied RSA private-key body.

    Local limits: 8192 ASCII key characters, canonical PKCS1/PKCS8 DER body,
    RSA 2048/3072/4096 bits, one exact modulus-sized ciphertext. The native PEM
    wrapper remains source evidence; this backend reads DER to support the
    PKCS8 body observed in the public GMC2 response without a misleading PEM
    label. Native PEM parser acceptance is not claimed. Return raw plaintext
    bytes. Input key and plaintext are never included in errors.
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
    try:
        key = serialization.load_der_private_key(key_der, password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size not in (2048, 3072, 4096):
            raise ValueError
        encodings = tuple(key.private_bytes(serialization.Encoding.DER, fmt, serialization.NoEncryption())
                          for fmt in (serialization.PrivateFormat.TraditionalOpenSSL, serialization.PrivateFormat.PKCS8))
        if key_der not in encodings:
            raise ValueError
        if len(encrypted) != key.key_size//8:
            raise ValueError
        return key.decrypt(encrypted, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                  algorithm=hashes.SHA256(), label=None))
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ValueError('Invalid SDK secret key or ciphertext') from None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate SDK constant')
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('Non-JSON SDK constant')


def _finite_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError('Nonfinite SDK number')
    return value


def decode_sdk_secret_constants(decrypted_list: str, key_body: str) -> dict:
    """Decode the secret-list JSON text after its outer UTF-16 XOR stage.

    Limits: 2048 UTF-16 units, 16 chunks, 8192 plaintext bytes. Decode all chunks
    before returning a dict. Strip one trailing NUL per chunk, as in the native
    UTF-8 conversion path. JSON duplicates/nonfinite values and invalid UTF-8
    are rejected explicitly; native tolerance for these is not asserted.
    """
    if not isinstance(decrypted_list, str) or len(decrypted_list) > 2048:
        raise ValueError('Invalid SDK secret list')
    if len(decrypted_list.encode('utf-16le', 'surrogatepass')) > 4096:
        raise ValueError('SDK secret list exceeds local budget')
    try:
        chunks = json.loads(decrypted_list, parse_constant=_reject_constant)
        if not isinstance(chunks, list) or len(chunks) > 16 or any(not isinstance(c, str) or not c for c in chunks):
            raise ValueError
        fragments, total = [], 0
        for chunk in chunks:
            raw = decrypt_sdk_secret_chunk(chunk, key_body).removesuffix(b'\0')
            if not raw:
                raise ValueError
            total += len(raw)
            if total > 8192:
                raise ValueError
            fragments.append(raw.decode('utf-8'))
        text = '{'+','.join(fragments)+'}'
        return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant,
                          parse_float=_finite_float)
    except (ValueError, TypeError, RecursionError):
        raise ValueError('Invalid SDK secret configuration') from None
