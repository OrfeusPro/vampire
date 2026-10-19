"""Bounded ID110 body reader; field offsets do not imply game semantics."""
from dataclasses import dataclass,field
import math
import struct

from .login_result import _text

SOURCE_SHA256='c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'


@dataclass(frozen=True,slots=True)
class SelectionRecord:
    """Immutable data fields keyed by native byte offset, with vtables omitted.

    Nested records/arrays preserve grouping. Time wrappers are flattened to the
    offset of their raw uint64 payload. No identifier, unit or timestamp meaning
    is assigned. A successful decode does not establish an accepted session.
    """
    fields: tuple=field(repr=False)

    def at(self,offset):
        for key,value in self.fields:
            if key==offset:return value
        raise KeyError(offset)


@dataclass(frozen=True,slots=True)
class WireVector3:
    """Three original float32 bit patterns; no coordinate/world claim."""
    bits: tuple[int,int,int]=field(repr=False)

    def finite_values(self):
        values=struct.unpack('<fff',struct.pack('<III',*self.bits))
        if not all(math.isfinite(v) for v in values):raise ValueError('Nonfinite selection vector')
        return values


@dataclass(frozen=True,slots=True)
class WireHeading:
    """Original wire byte, before native signed-angle canonicalization."""
    raw_byte: int=field(repr=False)


@dataclass(frozen=True,slots=True)
class CharacterSelectResultBody:
    result_code: int
    data: SelectionRecord=field(repr=False)

    @property
    def player(self):return self.data.at(0x18)


def decode_character_select_result(body,*,max_payload_size,max_collection_items):
    """Consume one complete ID110 body with an aggregate wire-entry budget.

    Every array/map entry consumes budget, including entries overwritten by a
    duplicate key and their nested entries. Maps return sorted (key, record)
    pairs, or None when absent; present-empty maps return (). Strings use the
    same strict local UTF-8 policy as the existing login/list codecs.
    """
    if type(max_payload_size) is not int or not 203<=max_payload_size<=0xffffff:
        raise ValueError('Selection result byte budget must be 203..16777215')
    if type(max_collection_items) is not int or not 0<=max_collection_items<=65535:
        raise ValueError('Selection result collection budget must be 0..65535')
    if type(body) is not bytes:raise ValueError('Selection result requires immutable bytes')
    if len(body)>max_payload_size:raise BufferError('Selection result exceeds byte budget')
    position=0

    def take(size):
        nonlocal position
        end=position+size
        if end>len(body):raise ValueError('Truncated selection result')
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
        except UnicodeDecodeError as exc:raise ValueError('Invalid selection UTF-8') from exc
        try:_text(value)
        except ValueError as exc:raise ValueError('Unsupported selection text') from exc
        return value

    def count():
        nonlocal max_collection_items
        n=u16()
        if n>max_collection_items:raise BufferError('Selection collections exceed aggregate budget')
        max_collection_items-=n;return n

    def array(item):return tuple(item() for _ in range(count()))

    def optional_map(item):
        if not flag():return None
        entries={}
        for _ in range(count()):
            key=byte();entries[key]=item()
        return tuple(sorted(entries.items()))

    def appearance_item():return record(((8,u32()),(12,min(byte(),45)),(14,u16())))

    def appearance():
        fields=[(8,min(byte(),2))]+[(offset,byte()) for offset in range(9,18)]
        fields.extend(((0x18,text()),(0x28,flag()),(0x29,byte()),(0x30,array(appearance_item))))
        return record(fields)

    def small_map_value():
        return record(((8,min(byte(),9)),(12,u32()),(16,u32()),(20,u32()),(0x20,u64())))

    def large_array_item():
        return record(((8,byte()),(9,min(byte(),2)),(12,u32()),(16,u32())))

    def large_map_value():
        fields=[(8,u64()),(0x10,u64()),(0x18,u32()),(0x1c,u32()),(0x20,u16()),(0x22,u16()),
            (0x24,u32()),(0x28,min(byte(),3)),(0x38,u64()),(0x48,u64()),(0x50,array(large_array_item)),(0x60,u32())]
        fields.extend((offset,flag()) for offset in range(0x64,0x68))
        fields.extend(((0x78,u64()),(0x80,u32()),(0x88,array(u32)),(0x98,flag()),(0xa8,u64()),
            (0xb0,u32()),(0xc0,u64()),(0xc8,byte()),(0xc9,flag()),(0xcc,u32()),(0xd8,u64())))
        return record(fields)

    def item158():return record(((8,u32()),(12,u16())))

    def item178():
        return record(((8,byte()),(12,u32()),(16,flag()),(32,flag()),(34,u16()),
            (48,flag()),(50,u16()),(56,byte()),(57,flag())))

    def item1c8():return record(((8,u32()),(16,u64())))
    def item1d8():return record(((8,min(byte(),91)),(16,u64())))

    def item1f8():
        fields=[(8,u64()),(16,u32()),(20,u32()),(24,u16()),(26,u16()),(28,u16()),
            (32,u64()),(40,u64()),(48,u64()),(56,u32())]
        present=flag();fields.append((72,present))
        bits=(u32(),u32(),u32()) if present else (0,0,0)
        fields.extend(zip((88,92,96),bits));fields.append((104,flag()))
        return record(fields)

    def item250():return record(((8,byte()),(9,min(byte(),7)),(10,byte())))
    def item290():return record(((8,u32()),(12,u32()),(16,u32()),(20,min(byte(),3))))

    code=u32()
    player=record(((8,u64()),(0x10,u64()),(0x18,flag()),(0x20,text()),(0x30,u32()),
        (0x34,min(byte(),6)),(0x38,u32()),(0x48,u32()),(0x4c,min(byte(),2)),(0x50,appearance()),
        (0x98,optional_map(large_map_value)),(0xf8,optional_map(small_map_value)),
        (0x158,array(item158)),(0x168,array(u32)),(0x178,array(item178)),(0x188,vector()),
        (0x1a0,WireHeading(byte())),(0x1c8,array(item1c8)),(0x1d8,array(item1d8)),(0x1e8,flag()),
        (0x1f0,u64()),(0x1f8,array(item1f8)),(0x208,u64()),(0x210,u64()),(0x218,min(byte(),6)),
        (0x220,array(u32)),(0x230,u64()),(0x238,array(byte)),(0x248,byte()),(0x250,array(item250)),
        (0x260,min(byte(),3)),(0x268,u64()),(0x270,u64())))
    block290=record(((8,flag()),(16,array(item290))))
    raw2b0=u64()
    block2b8=record(((8,u64()),(0x10,text()),(0x20,u32()),(0x28,tuple(u16() for _ in range(4))),
        (0x38,u64()),(0x40,min(byte(),6)),(0x50,u64()),(0x58,flag())))
    data=record(((0x18,player),(0x290,block290),(0x2b0,raw2b0),(0x2b8,block2b8),(0x320,u64()),
        (0x328,text()),(0x338,text()),(0x348,flag()),(0x349,flag())))
    if position!=len(body):raise ValueError('Trailing bytes after selection result')
    return CharacterSelectResultBody(code,data)
