"""Source-bound ID324 wire record; actor, visibility and world semantics are separate."""
from dataclasses import dataclass,field
import struct

from .character_select_result import SelectionRecord,WireVector3,WireHeading
from .npc_move_event import decode_npc_move_data
from .login_result import _text

SOURCE_SHA256='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


@dataclass(frozen=True,slots=True)
class NpcCreateNotify:
    flag:bool
    data:SelectionRecord=field(repr=False)

    @property
    def npc(self):return self.data.at(8)


def decode_npc_create_notify(body,*,source_sha256,max_collection_items=1024):
    """Consume exactly one body, charging every nested wire entry including duplicate keys.

    Offsets are native object offsets; no NPC ID/name/world meaning is assigned.
    Heading retains the original byte before native math canonicalization. Vector
    bits are retained, and require finite_values() before use as coordinates.
    """
    if source_sha256!=SOURCE_SHA256:raise ValueError('Unverified NPC create source')
    if type(body) is not bytes:raise TypeError('Immutable NPC create body required')
    if type(max_collection_items) is not int or not 0<=max_collection_items<=4096:
        raise ValueError('NPC create aggregate count limit must be 0..4096')
    if len(body)>65536:raise BufferError('NPC create byte limit')
    position=0
    def take(size):
        nonlocal position
        end=position+size
        if end>len(body):raise ValueError('Truncated NPC create body')
        value=body[position:end];position=end;return value
    def number(fmt):return struct.unpack('<'+fmt,take(struct.calcsize('<'+fmt)))[0]
    def byte():return number('B')
    def u16():return number('H')
    def u32():return number('I')
    def u64():return number('Q')
    def flag():return bool(byte())
    def record(fields):return SelectionRecord(tuple(fields))
    def text():
        encoded=take(u16())
        try:value=encoded.decode('utf-8')
        except UnicodeDecodeError as exc:raise ValueError('Invalid NPC create UTF-8') from exc
        _text(value);return value
    def count():
        nonlocal max_collection_items
        value=u16()
        if value>max_collection_items:raise BufferError('NPC create aggregate collection limit')
        max_collection_items-=value;return value
    def array(item):return tuple(item() for _ in range(count()))
    def optional(item):return item() if flag() else None
    def effect():
        fields=[(8,u64()),(0x10,u32()),(0x14,u32()),(0x18,u16()),(0x1a,u16()),(0x1c,u16()),
            (0x20,u64()),(0x28,u64()),(0x30,u64()),(0x38,u32())]
        present=flag();fields.append((0x48,present))
        bits=(u32(),u32(),u32()) if present else (0,0,0)
        fields.extend(zip((0x58,0x5c,0x60),bits));fields.append((0x68,flag()))
        return record(fields)
    def appearance_item():return record(((8,u32()),(12,min(byte(),45)),(14,u16())))
    def appearance():
        fields=[(8,min(byte(),2))]+[(offset,byte()) for offset in range(9,18)]
        fields.extend(((0x18,text()),(0x28,flag()),(0x29,byte()),(0x30,array(appearance_item))))
        return record(fields)
    def small_map():
        values={}
        for _ in range(count()):
            key=byte();values[key]=record(((8,min(byte(),9)),(12,u32()),(16,u32()),(20,u32()),(0x20,u64())))
        return tuple(sorted(values.items()))
    def param():return record(((8,flag()),(0x10,u64()),(0x18,u64())))
    def stat():return record(((8,u32()),(0x10,u64())))
    def move():
        n=count();return decode_npc_move_data(struct.pack('<H',n)+take(n*8),source_sha256=source_sha256,max_records=n)
    def owner():return record(((8,min(byte(),9)),(0x10,u64()),(0x18,text()),(0x28,u64())))
    def quest():return record(((8,u64()),(0x10,u64())))
    outer_flag=flag()
    npc=record(((8,u64()),(0x10,u32()),(0x18,WireVector3((u32(),u32(),u32()))),(0x30,WireHeading(byte())),
        (0x58,u64()),(0x60,u64()),(0x68,u64()),(0x70,flag()),(0x74,u32()),(0x78,u64()),
        (0x80,array(effect)),(0x90,min(byte(),22)),(0x98,optional(param)),(0xc8,optional(appearance)),
        (0x118,optional(small_map)),(0x178,array(stat)),(0x188,u64()),(0x190,u64())))
    data=record(((8,npc),(0x1a0,u32()),(0x1a8,move()),(0x1c0,u64()),(0x1c8,optional(owner)),
        (0x208,optional(quest)),(0x230,min(byte(),22)),(0x234,u32()),(0x238,u32())))
    if position!=len(body):raise ValueError('Trailing NPC create bytes')
    return NpcCreateNotify(outer_flag,data)
