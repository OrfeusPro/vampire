"""Bounded GMC2 UTF-16 code-unit XOR; outer response decoding is unresolved.

Evidence: HEADLESS-SDK-VALUES.md. Inputs are explicit UTF-16LE bytes, without
an added FString terminator. This is separate from the TCP frame XOR.
"""


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
