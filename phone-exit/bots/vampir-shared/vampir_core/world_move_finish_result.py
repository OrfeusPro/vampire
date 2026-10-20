"""Bounded complete ID206 body decoder; offsets preserve unknown semantics."""
from dataclasses import dataclass,field
import struct

from .character_select_result import SelectionRecord,WireVector3,WireHeading,SOURCE_SHA256
from .login_result import _text


@dataclass(frozen=True,slots=True)
class WorldMoveFinishResultBody:
    result_code: int
    data: SelectionRecord=field(repr=False)


def decode_world_move_finish_result(body,*,max_payload_size,max_collection_items):
    """Consume exactly one ID206 body with an aggregate wire-entry budget.

    No acceptance, readiness or world-coordinate semantics are inferred.
    Vtables omitted; raw time payload is exposed at its native field offset.
    """
    if type(max_payload_size) is not int or not 81<=max_payload_size<=0xffffff:
        raise ValueError('World result byte budget must be 81..16777215')
    if type(max_collection_items) is not int or not 0<=max_collection_items<=65535:
        raise ValueError('World result collection budget must be 0..65535')
    if type(body) is not bytes:raise ValueError('World result requires immutable bytes')
    if len(body)>max_payload_size:raise BufferError('World result exceeds byte budget')
    position=0

    def take(size):
        nonlocal position
        end=position+size
        if end>len(body):raise ValueError('Truncated world result')
        data=body[position:end];position=end;return data

    def number(fmt):return struct.unpack('<'+fmt,take(struct.calcsize('<'+fmt)))[0]
    def byte():return number('B')
    def u16():return number('H')
    def u32():return number('I')
    def u64():return number('Q')
    def flag():return bool(byte())
    def record(fields):return SelectionRecord(tuple(fields))
    def vector():return WireVector3((u32(),u32(),u32()))

    def text():
        encoded=take(u16())
        try:value=encoded.decode('utf-8')
        except UnicodeDecodeError as exc:raise ValueError('Invalid world UTF-8') from exc
        try:_text(value)
        except ValueError as exc:raise ValueError('Unsupported world text') from exc
        return value

    def array(item):
        nonlocal max_collection_items
        n=u16()
        if n>max_collection_items:raise BufferError('World collections exceed aggregate budget')
        max_collection_items-=n
        return tuple(item() for _ in range(n))

    def appearance_item():return record(((8,u32()),(12,min(byte(),45)),(14,u16())))

    def appearance():
        fields=[(8,min(byte(),2))]+[(offset,byte()) for offset in range(9,18)]
        fields.extend(((0x18,text()),(0x28,flag()),(0x29,byte()),(0x30,array(appearance_item))))
        return record(fields)

    def item_b8():return record(((8,u32()),(16,u64())))

    def item_c8():
        fields=[(8,u64()),(16,u32()),(20,u32()),(24,u16()),(26,u16()),(28,u16()),
            (32,u64()),(40,u64()),(48,u64()),(56,u32())]
        present=flag();fields.append((72,present))
        bits=(u32(),u32(),u32()) if present else (0,0,0)
        fields.extend(zip((88,92,96),bits));fields.append((104,flag()))
        return record(fields)

    def item_e8():
        fields=[(8,min(byte(),5)),(12,u32()),(16,u64()),(24,u64())]
        present=flag();fields.append((0x28,present))
        spatial=record(((8,vector()),(0x20,WireHeading(byte())))) if present else None
        fields.append((0x30,spatial));return record(fields)

    code=u32()
    data=record(((0x18,u64()),(0x20,u32()),(0x24,u32()),(0x28,flag()),(0x29,min(byte(),22)),
        (0x30,vector()),(0x48,WireHeading(byte())),(0x70,min(byte(),5)),(0x71,byte()),
        (0x78,appearance()),(0xb8,array(item_b8)),(0xc8,array(item_c8)),(0xe0,u64()),
        (0xe8,array(item_e8)),(0xf8,u16()),(0x100,array(u32)),(0x110,u64()),
        (0x118,min(byte(),100)),(0x119,flag())))
    if position!=len(body):raise ValueError('Trailing bytes after world result')
    return WorldMoveFinishResultBody(code,data)
