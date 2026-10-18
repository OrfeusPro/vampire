"""Bounded GMC2 string unescape and XOR; response extraction is unresolved.

Evidence: HEADLESS-SDK-VALUES.md. Inputs are explicit UTF-16LE bytes, without
an added FString terminator. This is separate from the TCP frame XOR.
"""
import base64
import json


def xor_sdk_utf16le(data: bytes, key: bytes) -> bytes:
    """Transform at most 2048 code units with at most 512 repeating key units.

    Preserve zero units and isolated surrogates. Callers must separately verify
    the response envelope, key source, text encoding and JSON schema.
    """
    if not isinstance(data, bytes) or not isinstance(key, bytes):
        raise ValueError('Expected immutable UTF-16LE byte strings')
    if len(data) > 4096 or len(key) > 1024 or len(data) % 2 or len(key) % 2:
        raise ValueError('SDK XOR input exceeds local bounds or has a partial code unit')
    if data and not key:
        raise ValueError('Nonempty SDK XOR input requires a key')
    result = bytearray(len(data))
    for offset in range(0, len(data), 2):
        key_offset = offset % len(key)
        result[offset] = data[offset] ^ key[key_offset]
        result[offset+1] = data[offset+1] ^ key[key_offset+1]
    return bytes(result)


def unescape_sdk_utf16le(content: bytes) -> bytes:
    """Decode a JSON string's content, without its surrounding quotes.

    Reject malformed escapes, raw quotes and raw controls instead of returning
    the partial result observed in the native helper. Preserve UTF-16 units.
    """
    if not isinstance(content, bytes) or len(content) > 4096 or len(content) % 2:
        raise ValueError('Expected bounded UTF-16LE string content')
    text = content.decode('utf-16le', 'surrogatepass')
    try:
        result = json.loads('"'+text+'"')
    except ValueError:
        raise ValueError('Malformed SDK string content') from None
    return result.encode('utf-16le', 'surrogatepass')


def decode_sdk_constants_string(content: bytes, key: bytes) -> bytes:
    """Unescape an extracted encrypted string, then XOR its UTF-16 units.

    Returns plaintext UTF-16LE bytes. Does not extract response fields, acquire
    a key, parse JSON, validate endpoints or decode encSecretConstants.
    """
    return xor_sdk_utf16le(unescape_sdk_utf16le(content), key)


def decode_sdk_base64(text: str) -> bytes:
    """Decode one standard Base64 ciphertext, padded or unpadded, up to 2048 chars.

    Reject noncanonical padding/bits and malformed input without exposing partial
    output. This does not parse secret-constant lists or perform RSA decryption.
    """
    if not isinstance(text, str) or len(text) > 2048:
        raise ValueError('Expected bounded SDK Base64 text')
    try:
        raw = text.encode('ascii')
        content = raw.rstrip(b'=')
        if len(raw)-len(content) > 2 or b'=' in content or len(content) % 4 == 1:
            raise ValueError
        decoded = base64.b64decode(content+b'='*(-len(content) % 4), validate=True)
        canonical = base64.b64encode(decoded)
        if raw not in (canonical, canonical.rstrip(b'=')):
            raise ValueError
    except ValueError:
        raise ValueError('Malformed SDK Base64 text') from None
    return decoded
