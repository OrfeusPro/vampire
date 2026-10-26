"""Source-bound PktGadget wire record; actor/world semantics remain separate."""
import struct
from .character_select_result import SelectionRecord,WireVector3,WireHeading
from .login_result import _text

SOURCE_SHA256='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


def decode_gadget(body,*,source_sha256,max_collection_items=1024):
    if source_sha256!=SOURCE_SHA256:raise ValueError('Unverified Gadget source')
    if type(body) is not bytes:raise TypeError('Immutable Gadget body required')
    if type(max_collection_items) is not int or not 0<=max_collection_items<=4096:raise ValueError('Gadget aggregate limit must be 0..4096')
    if len(body)>65536:raise BufferError('Gadget byte limit')
    position=0
    def take(size):
        nonlocal position
        end=position+size
        if end>len(body):raise ValueError('Truncated Gadget body')
        value=body[position:end];position=end;return value
    def number(fmt):return struct.unpack('<'+fmt,take(struct.calcsize('<'+fmt)))[0]
    def text():
        encoded=take(number('H'))
        try:value=encoded.decode('utf-8')
        except UnicodeDecodeError as exc:raise ValueError('Invalid Gadget UTF-8') from exc
        _text(value);return value
    fields=[(8,number('Q'))]+[(offset,number('I')) for offset in (0x10,0x14,0x18)]
    fields.extend(((0x20,WireVector3(tuple(number('I') for _ in range(3)))),(0x38,WireHeading(number('B'))),
        (0x60,bool(number('B'))),(0x61,min(number('B'),5)),(0x68,number('Q')),
        (0x70,number('I')),(0x74,min(number('B'),3))))
    count=number('H')
    if count>max_collection_items:raise BufferError('Gadget aggregate count limit')
    fields.append((0x78,tuple(number('Q') for _ in range(count))))
    owner=SelectionRecord(((8,min(number('B'),9)),(0x10,number('Q')),(0x18,text()),(0x28,number('Q')))) if number('B') else None
    fields.extend(((0x88,owner),(0xc8,number('B'))))
    if position!=len(body):raise ValueError('Trailing Gadget bytes')
    return SelectionRecord(tuple(fields))
