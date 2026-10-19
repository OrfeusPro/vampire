"""Verified PktVersion body layout, excluding ID/frame and semantic field names.

Strings follow writer order at offsets 10,28,38,48,58,68,78,88,a0,b0.
Integers follow offsets 20,98,c0. See HEADLESS-VERSION-PACKET-WRITER.md.
"""
from dataclasses import dataclass, field
import struct

SOURCE_SHA256 = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'


def _text_bytes(text):
    if type(text) is not str or len(text)>65535:
        raise ValueError('Expected bounded Version string')
    if any(c in text for c in ('\0','\ufffe','\uffff')):
        raise ValueError('Unsupported Version string code point')
    try:
        data=text.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise ValueError('Version string must contain Unicode scalar values') from exc
    if len(data)>65535:
        raise ValueError('Version UTF-8 string exceeds uint16 length')
    return data


@dataclass(frozen=True, slots=True)
class VersionPayload:
    """Raw ordered fields; no defaults inferred from a live client profile."""
    strings: tuple[str, ...] = field(repr=False)
    integers: tuple[int, int, int]

    def __post_init__(self):
        if type(self.strings) is not tuple or len(self.strings)!=10:
            raise ValueError('Version requires ten immutable ordered strings')
        if type(self.integers) is not tuple or len(self.integers)!=3:
            raise ValueError('Version requires three immutable ordered integers')
        for text in self.strings:_text_bytes(text)
        if any(type(v) is not int or not 0<=v<=0xffffffff for v in self.integers):
            raise ValueError('Expected unsigned Version uint32 values')

    def encode(self, *, max_payload_size):
        """Encode only the body; caller supplies an explicit local byte budget."""
        if type(max_payload_size) is not int or not 32<=max_payload_size<=0xffffff:
            raise ValueError('Version payload budget must be 32..16777215 bytes')
        strings=tuple(_text_bytes(text) for text in self.strings)
        if 32+sum(map(len,strings))>max_payload_size:
            raise BufferError('Version payload exceeds local byte budget')
        parts=[]
        for index,data in enumerate(strings):
            parts.extend((struct.pack('<H',len(data)),data))
            if index==0:parts.append(struct.pack('<I',self.integers[0]))
            if index==7:parts.append(struct.pack('<I',self.integers[1]))
        parts.append(struct.pack('<I',self.integers[2]))
        return b''.join(parts)
