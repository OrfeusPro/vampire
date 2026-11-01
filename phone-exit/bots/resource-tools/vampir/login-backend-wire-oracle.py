"""Pure Login bytes and frame expectations; checksum/transform are fixtures.

No native code or network is executed. Real integrity, encryption and transport
remain separate obligations. Expected bytes must never be copied into the native
archive to manufacture a passing observation.
"""
import struct

# Independent wire evidence defines ordered fields, including non-contiguous
# object offsets. This is not an iteration over a runtime-written archive.
FIELDS = (('string', 0x10), ('string', 0x20), ('string', 0x30), ('string', 0x40),
    ('u32', 0x50), ('string', 0x58), ('string', 0x68), ('string', 0x78), ('string', 0x88),
    ('u8', 0x98), ('u8', 0x99), ('string', 0xa0), ('u32', 0xb0), ('string', 0xb8),
    ('string', 0xc8), ('string', 0xd8), ('string', 0xe8), ('u32', 0xf8),
    ('string', 0x100), ('string', 0x110), ('u32', 0x120), ('u8', 0x124),
    ('u64', 0x128), ('bool', 0x130), ('bool', 0x131))
WIDTHS = {'u8': 1, 'u32': 4, 'u64': 8, 'bool': 1}


def require_unsigned(value, bits):
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError('Backend unsigned field differs')
    return value


def validate_schema(spec):
    if (not isinstance(spec, dict) or spec.get('object_size') != 320
            or spec.get('fields') != [list(field) for field in FIELDS]):
        raise ValueError('Backend Login wire schema differs')


def login_body(prepared):
    strings, integers = prepared.get('strings'), prepared.get('integers')
    if (not isinstance(strings, dict) or set(strings) != {hex(o) for k, o in FIELDS if k == 'string'}
            or not isinstance(integers, dict) or set(integers) != {hex(o) for k, o in FIELDS if k != 'string'}):
        raise ValueError('Backend prepared field inventory differs')
    out = bytearray()
    for kind, offset in FIELDS:
        if kind == 'string':
            text = strings[hex(offset)]
            if not isinstance(text, str) or '\0' in text:
                raise ValueError('Backend string differs')
            try:
                encoded = text.encode('utf-8')
                units = len(text.encode('utf-16le'))//2
            except UnicodeEncodeError as error:
                raise ValueError('Backend string encoding differs') from error
            if units+1 > 1024 or len(encoded) > 65535:
                raise ValueError('Backend string bound differs')
            out += struct.pack('<H', len(encoded)) + encoded
        else:
            value = require_unsigned(integers[hex(offset)], 8*WIDTHS[kind])
            # The source bool archive slot writes the raw byte. In particular,
            # SDK values 0x80/0xff must not be normalized to Python booleans.
            out += value.to_bytes(WIDTHS[kind], 'little')
    return bytes(out)


def frame(body, sequence, checksum=0x6a09e667):
    if not isinstance(body, bytes) or not 1 <= len(body) <= 1000:
        raise ValueError('Backend fixture body bound differs')
    require_unsigned(sequence, 16)
    require_unsigned(checksum, 32)
    inner = struct.pack('<HH', 3, sequence) + body
    length = len(inner)+7
    if length >= 1024:
        raise ValueError('Backend initial allocation frame bound differs')
    return length.to_bytes(3, 'little') + checksum.to_bytes(4, 'little') + inner


def validate_frame(actual, prepared, sequence, checksum=0x6a09e667):
    wanted = frame(login_body(prepared), sequence, checksum)
    if not isinstance(actual, bytes) or actual != wanted:
        raise ValueError('Backend native frame differs from independent Login expectation')
    return actual
