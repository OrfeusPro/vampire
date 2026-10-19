"""Whole ID110 collection readers with bounded allocation/cleanup fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('select_collections_base',HERE/'replay-character-select-result.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x

# Count offsets in the source-derived minimum profile, not native object offsets.
LAYOUT={0x80:(51,0x10,((8,4),(12,1),(14,2))),0x158:(55,0x10,((8,4),(12,2))),0x168:(57,4,((0,4),)),
    0x178:(59,0x40,((8,1),(12,4),(16,1),(32,1),(34,2),(48,1),(50,2),(56,1),(57,1))),
    0x1c8:(74,0x18,((8,4),(16,8))),0x1d8:(76,0x18,((8,1),(16,8))),
    0x1f8:(87,0x70,((8,8),(16,4),(20,4),(24,2),(26,2),(28,2),(32,8),(40,8),(48,8),(56,4),(72,1),(88,4),(92,4),(96,4),(104,1))),
    0x220:(106,4,((0,4),)),
    0x238:(116,1,((0,1),)),0x250:(119,0x10,((8,1),(9,1),(10,1))),0x290:(139,0x18,((8,4),(12,4),(16,4),(20,1)))}
FORMATS={0x80:'IBH',0x158:'IH',0x168:'I',0x178:'BIBBHBHBB',0x1c8:'IQ',0x1d8:'BQ',0x220:'I',0x238:'B',0x250:'BBB',0x290:'IIIB'}


def item_bytes(field,values):
    if field!=0x1f8:return struct.pack('<'+FORMATS[field],*values)
    return struct.pack('<QIIHHHQQQIB',*values[:11])+(struct.pack('<fff',*values[11:14]) if values[10] else b'')+bytes([values[14]])


def collection_body(arrays):
    data=base.basic_body((1.5,-2.25,3.75),45)
    for field,values in sorted(arrays.items(),key=lambda item:LAYOUT[item[0]][0],reverse=True):
        offset=LAYOUT[field][0]
        data=data[:offset]+struct.pack('<H',len(values))+b''.join(item_bytes(field,v) for v in values)+data[offset+2:]
    return data


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.empty_resize_callbacks.remove(0x1456b6000)
        self.empty_resize_callbacks.remove(0x1457846e0)
        self.collection_leaves=[]
        cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
        for address in (0x1457ec6b0,0x1457ec6d0,0x14577c9e0,0x1457ec890,0x14577ddd0,0x145815e20):
            off=self.image.offset(address-self.image.pe.base);rows=[]
            for ins in cs.disasm(self.raw[off:off+128],address):
                rows.append(ins)
                if ins.mnemonic=='ret':break
                if ins.mnemonic not in ('mov','lea','xor'):raise ValueError('Unreviewed collection constructor '+hex(address))
            if not rows or rows[-1].mnemonic!='ret':raise ValueError('Collection leaf boundary')
            end=rows[-1].address+rows[-1].size
            self.ranges.append((address,end));self.collection_leaves.append(dict(address=address,file_offset=off,bytes=self.raw[off:off+end-address].hex()))
        self.collection_allocators={0x141453c00:0x40,0x1414323e0:0x18,0x1414321b0:1,0x141432280:4,0x1415340d0:0x70}
        self.collection_cleanup={0x1457ed3c0,0x145789f70}
        for a in (*self.collection_allocators,*self.collection_cleanup):
            self.map_source_page(a & ~4095);self.map_source_page((a & ~4095)+4096)
        for lo,hi in self.ranges:
            for p in range(lo & ~4095,(hi+4095)&~4095,4096):self.map_source_page(p)

    def hook(self,uc,address,size,user):
        if address in self.collection_allocators:
            a=uc.reg_read(x.UC_X86_REG_RCX);count=uc.reg_read(x.UC_X86_REG_RDX)&0xffffffff
            if count>8:raise ValueError('Collection allocator count bound')
            pointer=self.alloc(count*self.collection_allocators[address]) if count else 0
            uc.mem_write(a,struct.pack('<Q',pointer));uc.mem_write(a+12,struct.pack('<I',count))
            self.finish(uc.reg_read(x.UC_X86_REG_RAX));return
        if address in self.collection_cleanup:
            self.finish(uc.reg_read(x.UC_X86_REG_RAX));return
        super().hook(uc,address,size,user)

    def read_collections(self,data):
        result=self.read_select(data);result['collections']={}
        for field,(_,stride,fields) in LAYOUT.items():
            descriptor=self.scratch+0x1000+(0x290+0x10 if field==0x290 else 0x18+field)
            pointer,count,capacity=struct.unpack('<QII',bytes(self.uc.mem_read(descriptor,16)))
            if not 0<=count<=capacity<=8:raise ValueError('Collection output bound '+hex(field))
            result['collections'][hex(field)]=[[int.from_bytes(self.uc.mem_read(pointer+i*stride+o,n),'little')
                for o,n in fields] for i in range(count)]
        return result


def build():
    em=Emulator();cases=[]
    values={0x80:((0,0,0),(0xffffffff,255,65535)),0x158:((0,0),(0xffffffff,65535)),0x168:((0,),(0xffffffff,)),
        0x178:((0,0,0,0,0,0,0,0,0),(255,0xffffffff,255,255,65535,255,65535,255,255)),
        0x1c8:((0,0),(0xffffffff,2**64-1)),0x1d8:((0,0),(255,2**64-1)),0x220:((0,),(0x80000000,)),
        0x1f8:((0,0,0,0,0,0,0,0,0,0,0,0.,0.,0.,0),(2**64-1,0xffffffff,0x80000000,65535,32768,1234,1,2,3,0xffffffff,255,1.5,-2.25,-0.,255)),
        0x238:((0,),(255,)),0x250:((0,0,0),(255,255,255)),0x290:((0,0,0,0),(0xffffffff,0x80000000,1234,255))}
    fixtures=[{field:(rows*n)[:n]} for field,rows in values.items() for n in (1,2,8)]
    fixtures.append(values)
    for arrays in fixtures:
        body=collection_body(arrays);c=em.read_collections(body)
        if c['returned']!=1 or c['consumed']!=len(body):raise ValueError('Nonempty collection reader failed')
        expected={hex(f):[list(v) for v in arrays.get(f,())] for f in LAYOUT}
        for v in expected['0x80']:v[1]=min(v[1],45)
        for v in expected['0x178']:
            for index in (2,3,5,8):v[index]=int(bool(v[index]))
        for v in expected['0x1d8']:v[0]=min(v[0],91)
        for v in expected['0x1f8']:
            v[10]=int(bool(v[10]));v[14]=int(bool(v[14]))
            v[11:14]=struct.unpack('<III',struct.pack('<fff',*v[11:14]))
        for v in expected['0x250']:v[1]=min(v[1],7)
        for v in expected['0x290']:v[3]=min(v[3],3)
        if c['collections']!=expected:raise ValueError('Collection native schema mismatch '+str(c))
        if c['vector188_hex']!=struct.pack('<ddd',1.5,-2.25,3.75).hex():raise ValueError('Collection shifted vector decoding')
        cases.append(c)
    body=collection_body(values)
    truncated=[em.read_collections(body[:n]) for n in range(len(body))]
    if any(c['returned']!=0 for c in truncated):raise ValueError('Truncated collection body accepted')
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),constructor_leaves=em.collection_leaves,
        dependency_sha256={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-character-select-result.py','replay-character-select-apply.py','replay-character-list-extensions.py')},
        source_ranges=em.result_ranges,cases=cases,truncated=truncated,native_execution=True,network_ready=False,
        limitations=['Actual outer/nested readers and item construction/append execute; bounded allocation and trivial cleanup captured.',
            'Eleven nonempty array fields covered; optional maps and other fields retain minimum-profile fixtures. No handler or live session.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-select-collections-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
