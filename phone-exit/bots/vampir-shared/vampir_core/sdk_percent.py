"""Strict printable ASCII subset of the observed SDK percent decoder.

Plus remains plus. Decode once; reject malformed escapes, %u, controls and
non-ASCII instead of reproducing the native helper's truncation/permissiveness.
"""


def decode_sdk_percent_ascii(value: str) -> str:
    if not isinstance(value, str) or len(value) > 32768 or any(not 32 <= ord(c) <= 126 for c in value):
        raise ValueError('Invalid bounded ASCII percent input')
    output = bytearray()
    index = 0
    hexadecimal = frozenset('0123456789abcdefABCDEF')
    while index < len(value):
        if value[index] == '%':
            if index + 2 >= len(value) or not all(c in hexadecimal for c in value[index + 1:index + 3]):
                raise ValueError('Malformed or unsupported SDK percent escape')
            byte = int(value[index + 1:index + 3], 16)
            index += 3
        else:
            byte = ord(value[index])
            index += 1
        if not 32 <= byte <= 126:
            raise ValueError('Decoded SDK value is outside printable ASCII')
        output.append(byte)
    return output.decode('ascii')
