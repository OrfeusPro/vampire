"""Compare decoded offsets with source-native records; no actor semantics."""
import math
import struct

SCALARS={
    'sight':{0x80:1},
    'character':{8:8,0x10:8,0x18:4,0x30:4,0x34:4,0x38:1,0x3c:4,0x80:2,0xd8:8,0xf0:1,0x228:1,0x229:1,0x22a:1,0x22b:1},
    'appearance':{8:1,**{i:1 for i in range(9,18)},0x28:1,0x29:1},'item':{8:4,12:1,14:2},'stat':{8:4,0x10:8},
    'effect':{8:8,0x10:4,0x14:4,0x18:2,0x1a:2,0x1c:2,0x20:8,0x28:8,0x30:8,0x38:4,0x48:1,0x58:4,0x5c:4,0x60:4,0x68:1},
    'action':{8:1,0xc:4,0x10:8,0x18:8},'guild':{8:8,0x20:4,0x38:8,0x40:1,0x50:8,0x58:1},
    'emblem':{8:2,10:2,12:2,14:2},'party':{8:8,0x48:1,0x49:1,0x4c:4},'options':{8:1,9:1,10:1,0x20:1,0x21:1},
    'npc_create':{0x1a0:4,0x1c0:8,0x230:1,0x234:4,0x238:4},
    'npc':{8:8,0x10:4,0x58:8,0x60:8,0x68:8,0x70:1,0x74:4,0x78:8,0x90:1,0x188:8,0x190:8},
    'param':{8:1,0x10:8,0x18:8},'owner':{8:1,0x10:8,0x28:8},'quest':{8:8,0x10:8},
    'gadget':{8:8,0x10:4,0x14:4,0x18:4,0x60:1,0x61:1,0x68:8,0x70:4,0x74:1,0xc8:1},
    'ground':{8:8,0x10:4,0x14:4,0x18:4,0x20:8,0x68:4,0x6c:4,0x70:1},
    'tether':{8:8,0x10:4,0x14:4,0x18:4,0x20:8,0x28:8,0x88:4,0x8c:1},
    'projectile':{8:2,0xc:4,0x10:4,0x14:4,0x18:8,0x38:2,0x68:8,0x70:4,0x74:4}}
ARRAYS={('sight',0x10):(0,0x230,'character'),('sight',0x20):(0,0x240,'npc_create'),('sight',0x30):(0,0x78,'ground'),
    ('sight',0x40):(0,0xd0,'gadget'),('sight',0x70):(0,0x90,'tether'),
    ('character',0xc8):(0,0x18,'stat'),('character',0xe0):(0,0x70,'effect'),('character',0xf8):(0,0x78,'action'),
    ('appearance',0x30):(0,16,'item'),('npc',0x80):(0,0x70,'effect'),('npc',0x178):(0,0x18,'stat'),
    ('npc_create',0x1a8):(8,16,'pair'),('gadget',0x78):(0,8,'u64')}
NESTED={('character',0x40):'appearance',('character',0x108):'guild',('guild',0x28):'emblem',
    ('party',0x20):'options',('npc_create',8):'npc',('circle',8):'projectile'}
OPTIONALS={('character',0x168):'party',('action',0x20):'position',('npc',0x98):'param',('npc',0xc8):'appearance',
    ('npc_create',0x1c8):'owner',('npc_create',0x208):'quest',('gadget',0x88):'owner'}
STRINGS={('character',0x20),('appearance',0x18),('guild',0x10),('party',0x10),('options',0x10),('owner',0x18)}
MAPS={('character',0x1c8),('npc',0x118)}


def compare(h,state,value,at,kind):
    from vampir_core.character_select_result import WireVector3,WireHeading
    uc=h.uc
    def require(ok,message):
        if not ok:raise ValueError('SightEnter '+kind+' '+message)
    def number(address,size=8):return int.from_bytes(uc.mem_read(address,size),'little')
    def live(pointer):return pointer in state['allocations'] and pointer not in state.get('string_freed',set())
    def array(items,address,stride,child):
        pointer,count,capacity=struct.unpack('<QII',bytes(uc.mem_read(address,16)))
        require(count==len(items) and count<=capacity<=8 and (not count or live(pointer)),'array ownership/count')
        for i,row in enumerate(items):
            entry=pointer+i*stride
            if child=='u64':require(number(entry)==row,'uint64 array value')
            elif child=='pair':require((number(entry+8,4),number(entry+12,4))==row.bits,'float pair bits')
            else:compare(h,state,row,entry,child)
    for offset,item in value.fields:
        key=(kind,offset)
        if key in STRINGS:
            pointer,count,capacity=struct.unpack('<QII',bytes(uc.mem_read(at+offset,16)))
            require(0<=count==capacity<=2048 and (not count or live(pointer)),'string ownership/count')
            data=bytes(uc.mem_read(pointer,count*2)) if count else b'\0\0'
            require(data[-2:]==b'\0\0' and data[:-2].decode('utf-16le')==item,'string value')
        elif key in ARRAYS:
            extra,stride,child=ARRAYS[key];array(item,at+offset+extra,stride,child)
        elif key==('sight',0x50):
            require(bool(number(at+0x58,1))==(item is not None),'projectiles presence')
            if item is not None:array(item,at+0x60,0x98,'circle')
        elif key in OPTIONALS:
            require(bool(number(at+offset+8,1))==(item is not None),'optional presence')
            if item is not None:compare(h,state,item,at+offset+0x10,OPTIONALS[key])
        elif key in NESTED:compare(h,state,item,at+offset,NESTED[key])
        elif key in MAPS:
            require(bool(number(at+offset+8,1))==(item is not None),'map presence')
            if item is not None:
                base=at+offset+0x10;pointer,count=number(base),number(base+8,4)
                require(count==len(item) and (not count or live(pointer)),'map ownership/count')
                actual=sorted((number(pointer+i*0x38,1),tuple(number(pointer+i*0x38+8+k,width) for k,width in ((8,1),(12,4),(16,4),(20,4),(0x20,8)))) for i in range(count))
                require(actual==[(k,tuple(row.at(n) for n in (8,12,16,20,0x20))) for k,row in item],'map fields')
        elif isinstance(item,WireVector3):
            expected=struct.unpack('<fff',struct.pack('<III',*item.bits));actual=struct.unpack('<ddd',bytes(uc.mem_read(at+offset,24)))
            for a,b in zip(actual,expected):require(math.isnan(a) if math.isnan(b) else struct.pack('<d',a)==struct.pack('<d',b),'XYZ value')
        elif not isinstance(item,WireHeading):require(number(at+offset,SCALARS[kind][offset])==item,'scalar '+hex(offset))
