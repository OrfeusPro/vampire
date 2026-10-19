"""Execute PktVersion writer, native UTF-8 conversion and archive primitives."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('version_ping',HERE/'build-headless-ping-codec.py')
ping=importlib.util.module_from_spec(spec);spec.loader.exec_module(ping)
native,x=ping.native,ping.x
WRITER=0x1456e5cf0
STRING_OFFSETS=(0x10,0x28,0x38,0x48,0x58,0x68,0x78,0x88,0xa0,0xb0)


class Emulator(ping.PingEmulator):
    def __init__(self):
        super().__init__()
        addresses=(WRITER,0x144aa6a30,0x144aa5fe0,0x144aa6060,0x141446a50,0x141440af0)
        self.writer_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in addresses})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.writer_fragments)
        leaf=0x141439820;off=self.image.offset(leaf-self.image.pe.base);content=self.raw[off:off+0x13d]
        cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
        rows=list(cs.disasm(content,leaf))
        if sum(i.size for i in rows)!=len(content) or rows[-1].mnemonic!='ret':raise ValueError('UTF-8 encoder leaf changed')
        self.encoder_leaf=dict(address=leaf,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest())
        self.ranges.append((leaf,leaf+len(content)))
        self.fixture_hooks={0x1414311c0,0x1468e4100,0x14147d580,0x14142c480,0x148796040}
        refs=[a for f in self.writer_fragments for r in f['instructions'] for a in r['rip_references']]
        pages={p for begin,end in self.ranges for p in range(begin&~4095,(end+4095)&~4095,4096)}
        pages.update(a&~4095 for a in (*refs,*self.fixture_hooks))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])

    def alloc(self,size):
        if not 0<=size<=8192 or self.heap+size>self.scratch+0x28000:raise ValueError('Writer allocation budget')
        result=self.heap;self.heap+=(max(size,1)+15)&~15
        self.uc.mem_write(result,b'\0'*max(size,1));return result

    def hook(self,uc,address,size,user):
        if address not in self.fixture_hooks and address!=ping.MEMCPY:return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==0x1414311c0:
            if b or d!=1:raise ValueError('UTF-8 scratch allocation changed')
            uc.mem_write(a,struct.pack('<Q',self.alloc(c)))
        elif address==0x1468e4100:result=self.alloc(a)
        elif address==0x148796040:result=uc.reg_read(x.UC_X86_REG_RAX)
        elif address==ping.MEMCPY:
            if c>8192 or not all(self.scratch<=p<=self.scratch+0x40000-c for p in (a,b)):raise ValueError('Writer memcpy bounds')
            uc.mem_write(a,bytes(uc.mem_read(b,c)));result=a;self.copy_sizes.append(c)
        elif address in (0x14147d580,0x14142c480):pass
        uc.reg_write(x.UC_X86_REG_RAX,result)
        stack=uc.reg_read(x.UC_X86_REG_RSP);ret=int.from_bytes(uc.mem_read(stack,8),'little')
        uc.reg_write(x.UC_X86_REG_RSP,stack+8);uc.reg_write(x.UC_X86_REG_RIP,ret)

    def execute_writer(self,strings,integers):
        if len(strings)!=10 or len(integers)!=3:raise ValueError('Version field arity')
        self.heap=self.scratch+0x10000;self.copy_sizes=[];self.io_entries=[]
        packet,archive,buffer=self.scratch+0x1000,self.scratch+0x2000,self.scratch+0x8000
        self.uc.mem_write(packet,b'\0'*0xd0);self.uc.mem_write(archive,b'\0'*128)
        for offset,text in zip(STRING_OFFSETS,strings):
            data=text.encode('utf-16le')+b'\0\0';p=self.alloc(len(data));self.uc.mem_write(p,data)
            self.uc.mem_write(packet+offset,struct.pack('<QII',p,len(data)//2,len(data)//2))
        for offset,value in zip((0x20,0x98,0xc0),integers):self.uc.mem_write(packet+offset,struct.pack('<I',value))
        self.call(0x144aa62f0,archive,1)
        self.uc.mem_write(archive+0x18,struct.pack('<QQQ',buffer,buffer,buffer+8192))
        self.uc.mem_write(archive+0x30,struct.pack('<III',8192,0,0))
        stack=self.scratch+0x30000;stop=self.scratch+0x3f000
        self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,packet),(x.UC_X86_REG_RDX,archive)):self.uc.reg_write(reg,value)
        self.uc.emu_start(WRITER,stop,count=200000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('Version writer instruction budget')
        size=int.from_bytes(self.uc.mem_read(archive+0x34,4),'little')
        if size>8192:raise ValueError('Version writer buffer budget')
        return dict(strings=list(strings),integers=list(integers),returned=self.uc.reg_read(x.UC_X86_REG_AL),
            payload_hex=bytes(self.uc.mem_read(buffer,size)).hex(),size=size)


def build():
    path=native.ROOT/'code-clues/connected-version-packet-replay.json'
    prior=json.loads(path.read_text('utf-8'));em=Emulator()
    if prior['sha256']!=em.bindings['sha256']:raise ValueError('Version writer source mismatch')
    fixtures=[]
    for c in prior['cases']:
        p=c['packet']
        if p:fixtures.append((c['fixture']['name'],[p['strings'][hex(o)] for o in STRING_OFFSETS],[p['raw_20'],p['raw_98'],p['raw_c0']]))
    for text in ('','a','a'*15,'a'*16,'a'*127,'a'*128,'Ж界','🙂','é'*80):
        fixtures.append(('boundary-'+str(len(fixtures)),[text]+['']*9,[0,207,0xffffffff]))
    cases=[]
    for name,strings,integers in fixtures:
        c=em.execute_writer(strings,integers);c['name']=name
        # Independent byte-layout expectation. Native code did all conversion
        # and archive serialization; this check does not supply its output.
        out=bytearray()
        for index,text in enumerate(strings):
            data=text.encode('utf-8');out.extend(struct.pack('<H',len(data)));out.extend(data)
            if index==0:out.extend(struct.pack('<I',integers[0]))
            if index==7:out.extend(struct.pack('<I',integers[1]))
        out.extend(struct.pack('<I',integers[2]))
        if c['payload_hex']!=out.hex() or c['returned']!=1:raise ValueError('Native Version layout differs')
        cases.append(c)
    table_off=em.image.offset(ping.WRITE_TABLE-em.image.pe.base)
    table=em.raw[table_off:table_off+0xd0]
    for slot,target in ((0x28,0x144aa5fe0),(0x60,0x144aa6060),(0xc8,0x144aa6090)):
        if struct.unpack_from('<Q',table,slot)[0]!=target:raise ValueError('Version archive slots changed')
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fragments=em.writer_fragments,encoder_leaf=em.encoder_leaf,archive_fragments=em.fragments,archive_leaves=em.leaves,
        archive_table=dict(address=ping.WRITE_TABLE,file_offset=table_off,bytes=table.hex(),sha256=hashlib.sha256(table).hexdigest()),
        cases=cases,native_execution=True,network_ready=False,
        limitations=['Actual Version writer, UTF-16 length/UTF-8 conversion and archive string/u16/u32/raw IO execute.',
            'Independent serialization run consumes earlier callback field snapshots, not full callback-to-frame execution.',
            'Allocator/free/cookie/memcpy bounded fixtures, preallocated archive capacity8192; no growth/OS allocator proof.',
            'Valid terminated strings only; embedded NUL/invalid UTF-16/truncation/failure propagation not covered.',
            'No frame/send/socket/server response, session, game launch/profile/process memory/credentials/network/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/version-packet-writer-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
