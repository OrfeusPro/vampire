"""Source-bound nested GuildTinyInfo/PartyTag wire records, without actor semantics."""
import struct
from .character_select_result import SelectionRecord
from .login_result import _text

SOURCE_SHA256='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


def _read(body,source_sha256,kind):
    if source_sha256!=SOURCE_SHA256:raise ValueError('Unverified social record source')
    if type(body) is not bytes:raise TypeError('Immutable social record required')
    if len(body)>65536:raise BufferError('Social record byte limit')
    position=0
    def take(size):
        nonlocal position
        end=position+size
        if end>len(body):raise ValueError('Truncated social record')
        value=body[position:end];position=end;return value
    def number(fmt):return struct.unpack('<'+fmt,take(struct.calcsize('<'+fmt)))[0]
    def text():
        encoded=take(number('H'))
        try:value=encoded.decode('utf-8')
        except UnicodeDecodeError as exc:raise ValueError('Invalid social record UTF-8') from exc
        _text(value);return value
    def record(fields):return SelectionRecord(tuple(fields))
    fields=[(8,number('Q')),(0x10,text())]
    if kind=='guild':
        fields.extend(((0x20,number('I')),(0x28,record((offset,number('H')) for offset in (8,10,12,14))),
            (0x38,number('Q')),(0x40,min(number('B'),6)),(0x50,number('Q')),(0x58,bool(number('B')))))
    else:
        options=record(((8,min(number('B'),3)),(9,min(number('B'),102)),(10,min(number('B'),8)),
            (0x10,text()),(0x20,bool(number('B'))),(0x21,bool(number('B')))))
        fields.extend(((0x20,options),(0x48,bool(number('B'))),(0x49,min(number('B'),3)),(0x4c,number('I'))))
    if position!=len(body):raise ValueError('Trailing social record bytes')
    return record(fields)


def decode_guild_tiny_info(body,*,source_sha256):
    """Time wrapper at +48 is flattened to its raw uint64 payload at +50."""
    return _read(body,source_sha256,'guild')


def decode_party_tag(body,*,source_sha256):
    return _read(body,source_sha256,'party')
