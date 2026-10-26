"""Two source-bound SightEnter wire records; no actor or effect semantics assigned."""
import struct
from .character_select_result import SelectionRecord,WireVector3,WireHeading

SOURCE_SHA256='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


def _read(body,source_sha256,kind):
    if source_sha256!=SOURCE_SHA256:raise ValueError('Unverified sight effect source')
    if type(body) is not bytes:raise TypeError('Immutable sight effect body required')
    expected=50 if kind=='ground' else 66
    if len(body)!=expected:raise ValueError('Sight effect body size differs')
    position=0
    def number(fmt):
        nonlocal position
        value=struct.unpack_from('<'+fmt,body,position)[0];position+=struct.calcsize('<'+fmt);return value
    def vector():return WireVector3(tuple(number('I') for _ in range(3)))
    fields=[(8,number('Q'))]+[(offset,number('I')) for offset in (0x10,0x14,0x18)]
    if kind=='ground':
        fields.extend(((0x20,number('Q')),(0x28,vector()),(0x40,WireHeading(number('B'))),
            (0x68,number('I')),(0x6c,number('I')),(0x70,min(number('B'),3))))
    else:
        fields.extend(((0x20,number('Q')),(0x28,number('Q')),(0x30,vector()),(0x48,vector()),
            (0x60,WireHeading(number('B'))),(0x88,number('I')),(0x8c,bool(number('B')))))
    return SelectionRecord(tuple(fields))


def decode_ground_effect_data(body,*,source_sha256):
    """Float at +6c retains raw uint32 bits; heading retains the wire byte."""
    return _read(body,source_sha256,'ground')


def decode_tether_effect_data(body,*,source_sha256):
    return _read(body,source_sha256,'tether')
