"""Source-bound PktLogin body, without inferred profile fields or network framing.

See HEADLESS-LOGIN-PACKET-WRITER.md for offsets, native vectors and limits.
"""
from dataclasses import dataclass, field
import struct

SOURCE_SHA256 = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'


def _utf8(text):
    if type(text) is not str or len(text) > 65535:
        raise ValueError('Expected bounded Login string')
    if any(c in text for c in ('\0', '\ufffe', '\uffff')):
        raise ValueError('Unsupported Login string code point')
    try:
        data = text.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise ValueError('Login string must contain Unicode scalar values') from exc
    if len(data) > 65535:
        raise ValueError('Login UTF-8 string exceeds uint16 length')
    return data


def _numbers(values, count, maximum):
    if type(values) is not tuple or len(values) != count:
        raise ValueError('Expected immutable ordered Login fields')
    if any(type(value) is not int or not 0 <= value <= maximum for value in values):
        raise ValueError('Login numeric field outside unsigned range')


@dataclass(frozen=True, slots=True)
class LoginPayload:
    """All fields explicit. Raw bytes, including bool slots, are not normalized.

    strings: offsets10,20,30,40,58,68,78,88,a0,b8,c8,d8,e8,100,110.
    integers: offsets50,b0,f8,120; raw_bytes: offsets98,99,124,130,131.
    raw_128: opaque uint64 at offset128; no semantic name/default inferred.
    """
    strings: tuple[str, ...] = field(repr=False)
    integers: tuple[int, ...] = field(repr=False)
    raw_bytes: tuple[int, ...] = field(repr=False)
    raw_128: int = field(repr=False)

    def __post_init__(self):
        if type(self.strings) is not tuple or len(self.strings) != 15:
            raise ValueError('Login requires fifteen immutable ordered strings')
        for text in self.strings:
            _utf8(text)
        _numbers(self.integers, 4, 0xffffffff)
        _numbers(self.raw_bytes, 5, 255)
        _numbers((self.raw_128,), 1, 0xffffffffffffffff)

    def encode(self, *, max_payload_size):
        """Encode the complete body atomically under an explicit local budget."""
        if type(max_payload_size) is not int or not 59 <= max_payload_size <= 0xffffff:
            raise ValueError('Login payload budget must be 59..16777215 bytes')
        texts = tuple(_utf8(text) for text in self.strings)
        if 59 + sum(map(len, texts)) > max_payload_size:
            raise BufferError('Login payload exceeds local byte budget')
        strings = tuple(struct.pack('<H', len(data))+data for data in texts)
        integers = tuple(struct.pack('<I', value) for value in self.integers)
        raw = tuple(bytes((value,)) for value in self.raw_bytes)
        return b''.join((*strings[:4], integers[0], *strings[4:8], raw[0], raw[1],
            strings[8], integers[1], *strings[9:13], integers[2], *strings[13:],
            integers[3], raw[2], struct.pack('<Q', self.raw_128), raw[3], raw[4]))
