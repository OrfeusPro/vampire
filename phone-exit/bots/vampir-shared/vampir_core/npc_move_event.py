"""Source-bound NPC movement wire records, without actor or map semantics."""
from dataclasses import dataclass,field
import math
import struct

SOURCE_SHA256='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


@dataclass(frozen=True,slots=True)
class FloatPair:
    bits:tuple[int,int]=field(repr=False)

    def finite_values(self):
        values=struct.unpack('<ff',struct.pack('<II',*self.bits))
        if not all(math.isfinite(v) for v in values):raise ValueError('Nonfinite NPC wire pair')
        return values


@dataclass(frozen=True,slots=True)
class NpcMoveNotify:
    entity_key:int=field(repr=False)
    xy:FloatPair=field(repr=False)
    records:tuple[FloatPair,...]=field(repr=False)


def _records(body,source_sha256,max_records,offset):
    if source_sha256!=SOURCE_SHA256:raise ValueError('Unverified NPC move source')
    if type(body) is not bytes:raise TypeError('Immutable NPC move body required')
    if type(max_records) is not int or not 0<=max_records<=4096:raise ValueError('NPC record limit must be 0..4096')
    if len(body)>65536:raise BufferError('NPC move byte limit')
    if len(body)<offset+2:raise ValueError('Truncated NPC move body')
    count=struct.unpack_from('<H',body,offset)[0]
    if count>max_records:raise BufferError('NPC move record limit')
    if len(body)!=offset+2+count*8:raise ValueError('NPC move body size differs')
    return tuple(FloatPair(struct.unpack_from('<II',body,offset+2+8*i)) for i in range(count))


def decode_npc_move_notify(body,*,source_sha256,max_records=1024):
    records=_records(body,source_sha256,max_records,16)
    key,x,y=struct.unpack_from('<QII',body)
    return NpcMoveNotify(key,FloatPair((x,y)),records)


def decode_npc_move_data(body,*,source_sha256,max_records=1024):
    return _records(body,source_sha256,max_records,0)
