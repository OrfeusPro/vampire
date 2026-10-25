"""Source-bound ID302 body; quest visibility records are separate from actor keys."""
from dataclasses import dataclass,field
import struct

SOURCE_SHA256='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


@dataclass(frozen=True,slots=True)
class SightLeaveNotify:
    actor_keys:tuple[int,...]=field(repr=False)
    quest_visible:tuple[tuple[int,int,int],...]=field(repr=False)
    reason:int


def decode_sight_leave_notify(body,*,source_sha256,max_collection_items=1024):
    if source_sha256!=SOURCE_SHA256:raise ValueError('Unverified sight leave source')
    if type(body) is not bytes:raise TypeError('Immutable sight leave body required')
    if type(max_collection_items) is not int or not 0<=max_collection_items<=4096:
        raise ValueError('Sight leave aggregate count limit must be 0..4096')
    if len(body)>65536:raise BufferError('Sight leave byte limit')
    if len(body)<5:raise ValueError('Truncated sight leave body')
    count=struct.unpack_from('<H',body)[0]
    if count>max_collection_items:raise BufferError('Sight leave aggregate count limit')
    position=2+count*8
    if position+3>len(body):raise ValueError('Truncated sight leave keys')
    keys=struct.unpack_from('<'+'Q'*count,body,2)
    records=struct.unpack_from('<H',body,position)[0]
    if records>max_collection_items-count:raise BufferError('Sight leave aggregate count limit')
    position+=2
    if len(body)!=position+records*24+1:raise ValueError('Sight leave body size differs')
    visible=tuple(struct.unpack_from('<QQQ',body,position+i*24) for i in range(records))
    return SightLeaveNotify(keys,visible,min(body[-1],32))
