"""Whole native ID206 reader; bounded fixtures and explicit schema profiles."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('finish_reader_base',HERE/'replay-character-select-fields.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.base.x
CTOR,READER=0x1458428a0,0x145844d70


def body_bytes(code=0,heading=0,text='',arrays=None,raw_type=0,enum70=0,enum118=0):
    arrays=arrays or {};encoded=text.encode('utf-8')
    appearance=bytes([255])+bytes(range(9))+struct.pack('<H',len(encoded))+encoded+bytes([255,255])
    appearance+=struct.pack('<H',len(arrays.get('appearance',())))+b''.join(struct.pack('<IBH',*v) for v in arrays.get('appearance',()))
    data=struct.pack('<IQIIBBfffBBB',code,0x123456789abcdef,0xffffffff,0x89abcdef,255,raw_type,1.5,-2.25,-0.,heading,enum70,255)+appearance
    for name,field in (('b8',0x1c8),('c8',0x1f8)):
        values=arrays.get(name,());data+=struct.pack('<H',len(values))+b''.join(base.base.base.item_bytes(field,v) for v in values)
    data+=struct.pack('<QH',0xfedcba9876543210,len(arrays.get('e8',())))
    # The nonempty e8 item schema is added only after its reader is reviewed.
    if arrays.get('e8'):raise ValueError('Nonempty e8 schema not yet established')
    values=arrays.get('100',())
    data+=struct.pack('<HH',65535,len(values))+b''.join(struct.pack('<I',v) for v in values)
    return data+struct.pack('<QBB',7,enum118,255)


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        manifest=json.loads((native.ROOT/'ghidra/entry-manifest.json').read_text('utf-8'))
        self.world_ranges=[r for f in manifest['functions'] if f['name'].startswith('WorldMoveFinishResult_') for r in f['ranges']]
        for r in self.world_ranges:
            lo,hi=int(r['start'],16),int(r['end_exclusive'],16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset']+hi-lo]).hexdigest()!=r['sha256']:
                raise ValueError('World reader source changed')
            self.ranges.append((lo,hi))
            for page in range(lo & ~4095,(hi+4095)&~4095,4096):self.map_source_page(page)
        self.world_leaves=[]
        cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
        for address in (0x14577d020,):
            off=self.image.offset(address-self.image.pe.base);rows=[]
            for ins in cs.disasm(self.raw[off:off+128],address):
                rows.append(ins)
                if ins.mnemonic=='ret':break
                if ins.mnemonic not in ('mov','lea','xor'):raise ValueError('Unreviewed world constructor leaf')
            if not rows or rows[-1].mnemonic!='ret':raise ValueError('World constructor leaf boundary')
            length=rows[-1].address+rows[-1].size-address
            self.world_leaves.append(dict(address=address,file_offset=off,bytes=self.raw[off:off+length].hex()))
            self.ranges.append((address,address+length));self.map_source_page(address & ~4095)
        self.world_hooks={0x1456b6020,0x1456b8980,0x145784520}
        for address in self.world_hooks:self.map_source_page(address & ~4095)

    def hook(self,uc,address,size,user):
        if address in self.world_hooks:
            if address==0x1456b8980:
                if uc.reg_read(x.UC_X86_REG_RDX):raise ValueError('Only fresh cleanup supported')
            else:
                count=uc.reg_read(x.UC_X86_REG_R8) & 65535
                if count:raise ValueError('Empty world resize boundary')
            self.finish(uc.reg_read(x.UC_X86_REG_RAX));return
        return super().hook(uc,address,size,user)

    def read_world(self,data):
        if len(data)>4096:raise ValueError('World body fixture bound')
        self.heap=self.scratch+0x10000;self.copy_sizes=[];self.io_entries=[];self.events=[]
        self.map_storage={};self.insertions=[]
        packet,archive,buffer=self.scratch+0x1000,self.scratch+0x3000,self.scratch+0x8000
        self.uc.mem_write(packet,bytes(0x800));self.uc.mem_write(buffer,bytes(4096));self.uc.mem_write(buffer,data)
        self.call(CTOR,packet);self.call(0x144aa6260,archive,buffer,len(data),1,0)
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000;self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,packet),(x.UC_X86_REG_RDX,archive)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(READER,stop,count=250000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('World reader instruction budget')
        p,n,cap=struct.unpack('<QII',bytes(self.uc.mem_read(packet+0x90,16)))
        text=bytes(self.uc.mem_read(p,(n-1)*2)).decode('utf-16le') if n else ''
        fields={hex(o):int.from_bytes(self.uc.mem_read(packet+o,size),'little') for o,size in
            ((0x10,4),(0x18,8),(0x20,4),(0x24,4),(0x28,1),(0x29,1),(0x70,1),(0x71,1),(0xe0,8),(0xf8,2),(0x110,8),(0x118,1),(0x119,1))}
        return dict(payload_hex=data.hex(),returned=self.uc.reg_read(x.UC_X86_REG_AL),
            consumed=int.from_bytes(self.uc.mem_read(archive+0x30,8),'little')-buffer,
            fields=fields,vector_hex=bytes(self.uc.mem_read(packet+0x30,24)).hex(),text=text,
            heading_byte=self.uc.mem_read(packet+0x60,1)[0])


def build():
    em=Emulator();cases=[]
    for text in ('','ASCII','Ж界🙂'):
        for enum in (0,255):
            for code in (0,1,0xffffffff):
                data=body_bytes(code=code,text=text,raw_type=enum,enum70=enum,enum118=enum,heading=45)
                c=em.read_world(data)
                if c['returned']!=1 or c['consumed']!=len(data) or c['text']!=text or c['fields']['0x10']!=code:
                    raise ValueError('Whole world reader mismatch')
                if (c['fields']['0x29'],c['fields']['0x70'],c['fields']['0x118'])!=(min(enum,22),min(enum,5),min(enum,100)):
                    raise ValueError('World enum clamp mismatch')
                cases.append(c)
    short=[];data=body_bytes()
    for size in range(len(data)):
        c=em.read_world(data[:size])
        if c['returned'] or c['consumed']>size:raise ValueError('Truncated world body accepted')
        short.append(dict(size=size,returned=c['returned'],consumed=c['consumed']))
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256=hashlib.sha256((HERE/'replay-character-select-fields.py').read_bytes()).hexdigest(),
        world_ranges=em.world_ranges,leaves=em.world_leaves,cases=cases,short=short,native_execution=True,network_ready=False,
        limitations=['Actual whole ID206 constructor/reader and reused vector/direction/appearance/primitive readers execute.',
            'Initial profile has empty arrays; nonempty e8 schema and portable full decoder remain open.',
            'Bounded allocator/cleanup/string/CRT math fixtures inherited from selection replays; no server IO/session/world coordinate claim.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/world-move-finish-reader-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']),short=len(report['short']))))
