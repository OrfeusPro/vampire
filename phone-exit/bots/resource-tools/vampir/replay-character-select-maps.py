"""Whole ID110 optional map readers with explicit bounded storage fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('select_maps_base',HERE/'replay-character-select-collections.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
extensions=base.base.base
VALUE_FIELDS=((8,8),(0x10,8),(0x18,4),(0x1c,4),(0x20,2),(0x22,2),(0x24,4),(0x28,1),
    (0x38,8),(0x48,8),(0x60,4),(0x64,1),(0x65,1),(0x66,1),(0x67,1),
    (0x78,8),(0x80,4),(0x98,1),(0xa8,8),(0xb0,4),(0xc0,8),(0xc8,1),(0xc9,1),(0xcc,4),(0xd8,8))


def value_fixture(seed=0,array50=(),array88=()):
    raw=(seed,2**64-1-seed,0xffffffff-seed,0x80000000+seed,65535-seed,32768+seed,
        0x12340000+seed,255,0x102030405060708+seed,0xfedcba9876543210-seed,
        seed*10,255,2,0,1,seed+101,0xffffffff-seed,255,seed+201,0x80000000+seed,
        seed+301,255,255,0xffffffff-seed,seed+401)
    return dict(raw=list(raw),array50=[list(v) for v in array50],array88=list(array88))


def value_bytes(value):
    raw=value['raw']
    return (struct.pack('<QQIIHHIBQQ',*raw[:10])+struct.pack('<H',len(value['array50']))
        +b''.join(struct.pack('<BBII',*v) for v in value['array50'])
        +struct.pack('<IBBBBQI',*raw[10:17])+struct.pack('<H',len(value['array88']))
        +b''.join(struct.pack('<I',v) for v in value['array88'])+struct.pack('<BQIQBBIQ',*raw[17:]))


def body_bytes(map98=None,mapf8=None,arrays=None,flag=255):
    data=base.base.basic_body((1.5,-2.25,3.75),45)
    replacements=[]
    if map98 is not None:
        replacements.append((53,1,struct.pack('<BH',flag,len(map98))+
            b''.join(bytes([key])+value_bytes(value) for key,value in map98)))
    if mapf8 is not None:replacements.append((54,1,extensions.optional_bytes(mapf8,flag)))
    for field,values in (arrays or {}).items():
        replacements.append((base.LAYOUT[field][0],2,struct.pack('<H',len(values))+
            b''.join(base.item_bytes(field,v) for v in values)))
    for offset,size,replacement in sorted(replacements,reverse=True):
        data=data[:offset]+replacement+data[offset+size:]
    return data


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.map98_address=self.scratch+0x1000+0x18+0xa8
        self.map98_hooks={0x1449d4b40,0x1456da5f0,0x1456e5ee0,0x1456e3b60,0x142dd2690}
        for a in self.map98_hooks:
            self.map_source_page(a & ~4095);self.map_source_page((a & ~4095)+4096)

    def init_map98(self,address):
        if address!=self.map98_address:raise ValueError('Unexpected large map receiver')
        pointer=self.map_storage.get(address)
        if pointer is None:pointer=self.alloc(8*0xf0);self.map_storage[address]=pointer
        self.uc.mem_write(address,bytes(0x50));self.uc.mem_write(pointer,bytes(8*0xf0))
        self.uc.mem_write(address,struct.pack('<QII',pointer,0,0))
        self.uc.mem_write(address+0x2c,struct.pack('<I',128))
        self.uc.mem_write(address+0x30,struct.pack('<i',-1));self.uc.mem_write(address+0x38,struct.pack('<i',-1))
        self.uc.mem_write(address+0x48,struct.pack('<I',1))

    def hook(self,uc,address,size,user):
        if address==0x1456b1610:
            pointer=uc.reg_read(x.UC_X86_REG_RCX);count=uc.reg_read(x.UC_X86_REG_RDX)&0xffffffff
            if count:
                if not 0<count<=8 or not self.scratch+0x10000<=pointer<=self.heap-count*0x18:
                    raise ValueError('Large value array cleanup fixture bound')
                self.finish(uc.reg_read(x.UC_X86_REG_RAX));return
        if address not in self.map98_hooks:return super().hook(uc,address,size,user)
        a,b=uc.reg_read(x.UC_X86_REG_RCX),uc.reg_read(x.UC_X86_REG_RDX)
        result=uc.reg_read(x.UC_X86_REG_RAX)
        if address in (0x1449d4b40,0x1456da5f0):
            if address==0x1456da5f0 and b:raise ValueError('Only fresh large map reset supported')
            self.init_map98(a)
        elif address==0x142dd2690:
            if a!=self.map98_address or b>=8:raise ValueError('Large map allocation fixture bound')
            uc.mem_write(a+12,struct.pack('<I',8))
        elif address==0x1456e5ee0:
            if a!=self.map98_address:raise ValueError('Large map insertion receiver')
            pointer,count=struct.unpack('<QI',bytes(uc.mem_read(a,12)))
            if not 1<=count<=8:raise ValueError('Large map insertion count bound')
            if any(int.from_bytes(uc.mem_read(pointer+i*0xf0,1),'little')==b for i in range(count-1)):
                raise ValueError('Duplicate incorrectly reached actual large map insertion')
            self.map98_insertions.append(b);result=0
        elif address==0x1456e3b60:
            if a!=self.map98_address:raise ValueError('Large map rehash receiver')
            pointer,count=struct.unpack('<QI',bytes(uc.mem_read(a,12)))
            buckets=int.from_bytes(uc.mem_read(a+0x48,4),'little')
            if not 1<=buckets<=16 or buckets & (buckets-1):raise ValueError('Large map bucket bound')
            heads=[-1]*buckets
            for index in range(count):
                node=pointer+index*0xf0;key=int.from_bytes(uc.mem_read(node,1),'little');bucket=key & (buckets-1)
                uc.mem_write(node+0xe8,struct.pack('<iI',heads[bucket],bucket));heads[bucket]=index
            p=self.alloc(4*buckets) if buckets>1 else a+0x38
            uc.mem_write(p,struct.pack('<'+'i'*buckets,*heads));uc.mem_write(a+0x40,struct.pack('<Q',p if buckets>1 else 0))
            self.map98_rehashes.append(buckets)
        self.finish(result)

    def read_maps(self,data):
        self.map98_insertions=[];self.map98_rehashes=[]
        result=self.read_collections(data)
        result['map98']=None
        if int.from_bytes(self.uc.mem_read(self.map98_address-8,1),'little'):
            pointer,count=struct.unpack('<QI',bytes(self.uc.mem_read(self.map98_address,12)))
            if not 0<=count<=8:raise ValueError('Large map output count bound')
            values=[]
            for i in range(count):
                node=pointer+i*0xf0;value=node+8
                raw=[int.from_bytes(self.uc.mem_read(value+o,n),'little') for o,n in VALUE_FIELDS]
                arrays={}
                for offset,stride,fields in ((0x50,0x18,((8,1),(9,1),(12,4),(16,4))),(0x88,4,((0,4),))):
                    p,n,capacity=struct.unpack('<QII',bytes(self.uc.mem_read(value+offset,16)))
                    if not 0<=n<=capacity<=8:raise ValueError('Nested large value array bound')
                    arrays[hex(offset)]=[[int.from_bytes(self.uc.mem_read(p+j*stride+o,s),'little') for o,s in fields] for j in range(n)]
                values.append(dict(key=int.from_bytes(self.uc.mem_read(node,1),'little'),raw=raw,
                    array50=arrays['0x50'],array88=[v[0] for v in arrays['0x88']]))
            result['map98']=sorted(values,key=lambda v:v['key'])
        result['mapf8']=None
        optional=self.scratch+0x1000+0x18+0xf8
        if int.from_bytes(self.uc.mem_read(optional+8,1),'little'):
            pointer,count=struct.unpack('<QI',bytes(self.uc.mem_read(optional+0x10,12)))
            if not 0<=count<=8:raise ValueError('Small map output count bound')
            result['mapf8']=sorted([[int.from_bytes(self.uc.mem_read(pointer+i*0x38+o,n),'little')
                for o,n in ((0,1),(0x10,1),(0x14,4),(0x18,4),(0x1c,4),(0x28,8))] for i in range(count)])
        result['map98_insertions']=self.map98_insertions.copy();result['map98_rehashes']=self.map98_rehashes.copy()
        return result


def normalized_value(key,value):
    raw=value['raw'].copy();raw[7]=min(raw[7],3)
    for i in (11,12,13,14,17,22):raw[i]=int(bool(raw[i]))
    return dict(key=key,raw=raw,array50=[[a,min(b,2),c,d] for a,b,c,d in value['array50']],array88=value['array88'].copy())


def main_arrays():
    return {0x80:((0xffffffff,255,65535),),0x158:((0xffffffff,65535),),0x168:((0xffffffff,),),
        0x178:((255,0xffffffff,255,255,65535,255,65535,255,255),),0x1c8:((0xffffffff,2**64-1),),
        0x1d8:((255,2**64-1),),0x1f8:((2**64-1,0xffffffff,0x80000000,65535,32768,1234,1,2,3,0xffffffff,255,1.5,-2.25,-0.,255),),
        0x220:((0xffffffff,),),0x238:((255,),),0x250:((255,255,255),),0x290:((0xffffffff,0x80000000,1234,255),)}


def build():
    em=Emulator();cases=[]
    small=((1,255,2,3,4,5),(9,2,3,4,5,6),(1,1,7,8,9,10))
    fixtures=[(None,None,{}),([],[],{})]
    for count in (0,1,2,8):
        value=value_fixture(count,tuple((i,255,0xffffffff-i,i) for i in range(count)),tuple(0xffffffff-i for i in range(count)))
        fixtures.extend([([(0,value)],None,{}),([(255,value)],small,{}),([(1,value),(9,value_fixture(2)),(1,value_fixture(3))],small,{})])
    collision=[(i*8+1,value_fixture(i,((255,255,i,0xffffffff-i),),(i,0xffffffff-i))) for i in range(8)]
    fixtures.extend([(collision,small,{}),(collision+[(1,value_fixture(10)),(9,value_fixture(11,((1,2,3,4),),(5,6)))],small,{})])
    dense=[(1,value_fixture(9,((255,255,0xffffffff,0x80000000),(0,0,0,0)),(0xffffffff,0x80000000)))]
    fixtures.append((dense,small,main_arrays()))
    for large,small_map,arrays in fixtures:
        data=body_bytes(large,small_map,arrays);c=em.read_maps(data)
        if c['returned']!=1 or c['consumed']!=len(data):raise ValueError('Whole map body rejected')
        expected=None if large is None else sorted({k:normalized_value(k,v) for k,v in large}.values(),key=lambda v:v['key'])
        if c['map98']!=expected:raise ValueError('Large map schema/duplicate mismatch '+str(c['map98']))
        expected_small=None if small_map is None else sorted({v[0]:[v[0],min(v[1],9),*v[2:]] for v in small_map}.values())
        if c['mapf8']!=expected_small:raise ValueError('Small map schema/duplicate mismatch')
        if c['map98_insertions']!=list(dict.fromkeys(k for k,_ in large or ())):raise ValueError('Large map duplicate insertion')
        if c['vector188_hex']!=struct.pack('<ddd',1.5,-2.25,3.75).hex():raise ValueError('Map shifted following vector')
        cases.append(c)
    # All prefixes of a nested value plus the second map.
    short_body=body_bytes(dense,small)
    truncated=[em.read_maps(short_body[:n]) for n in range(len(short_body))]
    if any(c['returned'] for c in truncated):raise ValueError('Truncated map body accepted')
    anchors=[]
    for address,length in ((0x1498d90b8,24),(0x1498cf350,40),(0x1498cf308,40),(0x1498f8700,24),(0x1498cf278,40)):
        off=em.image.offset(address-em.image.pe.base)
        anchors.append(dict(address=address,file_offset=off,bytes=em.raw[off:off+length].hex()))
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),source_ranges=em.result_ranges,anchors=anchors,
        dependency_sha256={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-character-select-collections.py','replay-character-select-result.py','replay-character-list-extensions.py')},
        cases=cases,truncated=truncated,native_execution=True,network_ready=False,
        limitations=['Actual whole ID110 readers, map item/find/insert/value construct/copy/destroy/read and nested array items execute.',
            'Map storage/reset, bounded allocation, fresh unseen-key insert predicate and hash-bucket rebuild are fixtures; duplicate lookup follows native chains.',
            'Array cleanup is a bounded capture, not native lifetime proof. No handler/session/game process/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-select-maps-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']),truncated=len(report['truncated']))))
