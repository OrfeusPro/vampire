"""Verified 1.13.18 stat fields; callers bind separate native proof evidence."""
import struct

SOURCE_SHA256='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'


from .stat_change import StatValue,StatChange


def decode_stat_change(body,*,source_sha256,max_records=1024):
    return _decode(body,source_sha256,max_records,tail=True)


def decode_character_level_up(body,*,source_sha256,max_records=1024):
    return _decode(body,source_sha256,max_records,tail=False)


def _decode(body,source_sha256,max_records,*,tail):
    if source_sha256!=SOURCE_SHA256:raise ValueError('Unverified stat source')
    if type(max_records) is not int or not 0<=max_records<=4096:raise ValueError('Stat record limit must be 0..4096')
    if type(body) is not bytes:raise TypeError('Immutable stat body required')
    if len(body)>65536:raise BufferError('Stat notification exceeds byte limit')
    minimum=13 if tail else 10
    if len(body)<minimum:raise ValueError('Truncated stat notification')
    key,count=struct.unpack_from('<QH',body)
    if count>max_records:raise BufferError('Stat notification exceeds record limit')
    if len(body)!=minimum+20*count:raise ValueError('Stat notification length differs')
    values=tuple(StatValue(*struct.unpack_from('<iQQ',body,10+20*i)) for i in range(count))
    flag,reason=struct.unpack_from('<BH',body,10+20*count) if tail else (None,None)
    return StatChange(key,values,bool(flag) if flag is not None else None,reason)


def initial_stat_values(records,*,source_sha256):
    """PktStat pairs from the verified PktCharacter +1c8 collection."""
    from .character_select_result import SelectionRecord
    if source_sha256!=SOURCE_SHA256:raise ValueError('Unverified initial stat source')
    if type(records) is not tuple or len(records)>1024:raise ValueError('Invalid initial stat collection')
    values=[]
    for record in records:
        if not isinstance(record,SelectionRecord) or tuple(k for k,v in record.fields)!=(8,16):
            raise ValueError('Initial stat record layout differs')
        stat,bits=record.at(8),record.at(16)
        if type(stat) is not int or not 0<=stat<2**32 or type(bits) is not int or not 0<=bits<2**64:
            raise ValueError('Initial stat fields differ')
        values.append((stat if stat<2**31 else stat-2**32,bits if bits<2**63 else bits-2**64))
    return tuple(values)
