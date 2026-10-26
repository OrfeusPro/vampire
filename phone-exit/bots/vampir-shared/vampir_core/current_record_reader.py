"""One bounded cursor/budget for source-verified nested 1.13.16 records."""
import struct
from .character_select_result import SelectionRecord,WireVector3,WireHeading
from .npc_move_event import decode_npc_move_data
from .login_result import _text

SOURCE_SHA256='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


class CurrentRecordReader:
    def __init__(self,body,*,source_sha256,max_collection_items=1024):
        if source_sha256!=SOURCE_SHA256:raise ValueError('Unverified nested record source')
        if type(body) is not bytes:raise TypeError('Immutable nested record body required')
        if type(max_collection_items) is not int or not 0<=max_collection_items<=4096:raise ValueError('Record aggregate limit must be 0..4096')
        if len(body)>65536:raise BufferError('Record byte limit')
        self.body=body;self.position=0;self.remaining=max_collection_items

    def take(self,size):
        end=self.position+size
        if size<0 or end>len(self.body):raise ValueError('Truncated nested record')
        value=self.body[self.position:end];self.position=end;return value

    def number(self,fmt):return struct.unpack('<'+fmt,self.take(struct.calcsize('<'+fmt)))[0]
    def byte(self):return self.number('B')
    def u16(self):return self.number('H')
    def u32(self):return self.number('I')
    def u64(self):return self.number('Q')
    def flag(self):return bool(self.byte())
    def record(self,fields):return SelectionRecord(tuple(fields))
    def xyz(self):return WireVector3((self.u32(),self.u32(),self.u32()))
    def yaw(self):return WireHeading(self.byte())

    def text(self):
        encoded=self.take(self.u16())
        try:value=encoded.decode('utf-8')
        except UnicodeDecodeError as exc:raise ValueError('Invalid nested UTF-8') from exc
        _text(value);return value

    def count(self):
        value=self.u16()
        if value>self.remaining:raise BufferError('Record aggregate collection limit')
        self.remaining-=value;return value

    def array(self,item):return tuple(item() for _ in range(self.count()))
    def optional(self,item):return item() if self.flag() else None
    def finish(self):
        if self.position!=len(self.body):raise ValueError('Trailing nested record bytes')

    def effect(self):
        fields=[(8,self.u64()),(0x10,self.u32()),(0x14,self.u32()),(0x18,self.u16()),(0x1a,self.u16()),(0x1c,self.u16()),
            (0x20,self.u64()),(0x28,self.u64()),(0x30,self.u64()),(0x38,self.u32())]
        present=self.flag();fields.append((0x48,present))
        bits=(self.u32(),self.u32(),self.u32()) if present else (0,0,0)
        fields.extend(zip((0x58,0x5c,0x60),bits));fields.append((0x68,self.flag()))
        return self.record(fields)

    def appearance_item(self):return self.record(((8,self.u32()),(12,min(self.byte(),45)),(14,self.u16())))
    def appearance(self):
        fields=[(8,min(self.byte(),2))]+[(offset,self.byte()) for offset in range(9,18)]
        fields.extend(((0x18,self.text()),(0x28,self.flag()),(0x29,self.byte()),(0x30,self.array(self.appearance_item))))
        return self.record(fields)

    def small_map(self):
        values={}
        for _ in range(self.count()):
            key=self.byte();values[key]=self.record(((8,min(self.byte(),9)),(12,self.u32()),(16,self.u32()),(20,self.u32()),(0x20,self.u64())))
        return tuple(sorted(values.items()))

    def param(self):return self.record(((8,self.flag()),(0x10,self.u64()),(0x18,self.u64())))
    def stat(self):return self.record(((8,self.u32()),(0x10,self.u64())))
    def move(self):
        count=self.count();return decode_npc_move_data(struct.pack('<H',count)+self.take(count*8),source_sha256=SOURCE_SHA256,max_records=count)
    def owner(self):return self.record(((8,min(self.byte(),9)),(0x10,self.u64()),(0x18,self.text()),(0x28,self.u64())))
    def quest(self):return self.record(((8,self.u64()),(0x10,self.u64())))

    def npc_create_data(self):
        npc=self.record(((8,self.u64()),(0x10,self.u32()),(0x18,self.xyz()),(0x30,self.yaw()),
            (0x58,self.u64()),(0x60,self.u64()),(0x68,self.u64()),(0x70,self.flag()),(0x74,self.u32()),(0x78,self.u64()),
            (0x80,self.array(self.effect)),(0x90,min(self.byte(),22)),(0x98,self.optional(self.param)),(0xc8,self.optional(self.appearance)),
            (0x118,self.optional(self.small_map)),(0x178,self.array(self.stat)),(0x188,self.u64()),(0x190,self.u64())))
        return self.record(((8,npc),(0x1a0,self.u32()),(0x1a8,self.move()),(0x1c0,self.u64()),(0x1c8,self.optional(self.owner)),
            (0x208,self.optional(self.quest)),(0x230,min(self.byte(),22)),(0x234,self.u32()),(0x238,self.u32())))

    def position_data(self):return self.record(((8,self.xyz()),(0x20,self.yaw())))

    def actor_action(self):
        return self.record(((8,min(self.byte(),5)),(0xc,self.u32()),(0x10,self.u64()),
            (0x18,self.u64()),(0x20,self.optional(self.position_data))))

    def guild(self):
        from .sight_social_records import decode_guild_tiny_info
        # Source-fixed prefix/tail around the sole length-prefixed string.
        start=self.position;self.take(8);self.take(self.u16()+30)
        return decode_guild_tiny_info(self.body[start:self.position],source_sha256=SOURCE_SHA256)

    def party(self):
        from .sight_social_records import decode_party_tag
        # The existing decoder remains responsible for fields and text policy.
        start=self.position;self.take(8);self.take(self.u16());self.take(3);self.take(self.u16());self.take(8)
        return decode_party_tag(self.body[start:self.position],source_sha256=SOURCE_SHA256)

    def character_other(self):
        return self.record(((8,self.u64()),(0x10,self.u64()),(0x18,self.u32()),(0x20,self.text()),
            (0x30,self.u32()),(0x34,self.u32()),(0x38,min(self.byte(),6)),(0x3c,self.u32()),
            (0x40,self.appearance()),(0x80,self.u16()),(0x88,self.xyz()),(0xa0,self.yaw()),
            (0xc8,self.array(self.stat)),(0xd8,self.u64()),(0xe0,self.array(self.effect)),(0xf0,self.flag()),
            (0xf8,self.array(self.actor_action)),(0x108,self.guild()),(0x168,self.optional(self.party)),
            (0x1c8,self.optional(self.small_map)),(0x228,self.flag()),(0x229,min(self.byte(),3)),
            (0x22a,self.flag()),(0x22b,min(self.byte(),3))))
