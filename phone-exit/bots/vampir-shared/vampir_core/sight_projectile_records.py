"""Source-bound SightEnter optional projectile array; no actor/ownership semantics."""
import struct
from .character_select_result import SelectionRecord,WireVector3,WireHeading

SOURCE_SHA256='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


def _circle(body):
    # Exact 65-byte circle = 53-byte projectile plus float32 XYZ.
    values=struct.unpack('<HIIIQIIIHBQIIIII',body)
    data=SelectionRecord(((8,values[0]),(0xc,values[1]),(0x10,values[2]),(0x14,values[3]),
        (0x18,values[4]),(0x20,WireVector3(values[5:8])),(0x38,values[8]),(0x40,WireHeading(values[9])),
        (0x68,values[10]),(0x70,values[11]),(0x74,values[12])))
    return SelectionRecord(((8,data),(0x80,WireVector3(values[13:16]))))


def decode_projectile_circle_data(body,*,source_sha256):
    if source_sha256!=SOURCE_SHA256:raise ValueError('Unverified projectile source')
    if type(body) is not bytes:raise TypeError('Immutable projectile body required')
    if len(body)!=65:raise ValueError('Projectile circle body size differs')
    return _circle(body)


def decode_optional_projectile_circles(body,*,source_sha256,max_collection_items=1024):
    if source_sha256!=SOURCE_SHA256:raise ValueError('Unverified projectile source')
    if type(body) is not bytes:raise TypeError('Immutable projectile body required')
    if type(max_collection_items) is not int or not 0<=max_collection_items<=4096:raise ValueError('Projectile aggregate limit must be 0..4096')
    if len(body)>65536:raise BufferError('Projectile byte limit')
    if not body:raise ValueError('Truncated projectile optional')
    if not body[0]:
        if len(body)!=1:raise ValueError('Trailing absent projectile data')
        return None
    if len(body)<3:raise ValueError('Truncated projectile count')
    count=struct.unpack_from('<H',body,1)[0]
    if count>max_collection_items:raise BufferError('Projectile aggregate count limit')
    if len(body)!=3+65*count:raise ValueError('Projectile array body size differs')
    return tuple(_circle(body[3+i*65:3+(i+1)*65]) for i in range(count))
