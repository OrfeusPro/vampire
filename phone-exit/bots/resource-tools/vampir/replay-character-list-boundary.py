"""Native post-Login reset versus separate CharacterList request entrypoints."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('character_boundary_base',HERE/'replay-version-packet-writer.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
INIT,RESET,GLOBAL,TABLE=0x14647f9f0,0x1464846c0,0x14b58b930,0x149c5f828
REQUESTS=(0x145dbd4b0,0x145dbfe50)
SEND=0x30002000


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.binding=next(p for p in self.bindings['packets'] if p['name']=='PktCharacterListRead')
        self.extra=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in (INIT,RESET,*REQUESTS)})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.extra)
        self.native_leaves=[]
        for address,length in ((0x146486a50,8),(0x144aaa9d0,8),(self.binding['constructor'],18),
            (self.binding['id_getter'],6),(self.binding['writer'],3)):
            offset=self.image.offset(address-self.image.pe.base);data=self.raw[offset:offset+length]
            self.native_leaves.append(dict(address=address,file_offset=offset,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest()))
            self.ranges.append((address,address+length))
        rows=[r for f in self.extra for r in f['instructions']]
        # Explicit external helpers, never inferred dynamically from arbitrary targets.
        self.helpers={0x1445d91c0,0x144280630,0x14145b150,0x1456c3960,0x141833c60,
            0x1425329a0,0x144ff8540,0x141530df0,0x1414d9eb0,0x1414b99f0,0x141634c10,
            0x141417180,0x146477da0,0x1414d2af0,0x141496240,0x1414323e0,0x14142e310,
            0x14167c120,0x141684b90,0x1414324d0,0x1415307f0,0x141427d70,
            0x14560dd00,0x141421150,0x1413fe190,0x14147d580,0x1456b2340,SEND}
        refs=[a for r in rows for a in r['rip_references']]
        pages={p for begin,end in self.ranges for p in range(begin & ~4095,(end+4095) & ~4095,4096)}
        pages.update(a & ~4095 for a in (*refs,*self.helpers,GLOBAL,TABLE,0x14b520d90,self.binding['vtable']))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:offset=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[offset:offset+4096])
        self.events=[]

    def hook(self,uc,address,size,user):
        if address not in self.helpers:return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==SEND:
            vptr=int.from_bytes(uc.mem_read(b,8),'little')
            if vptr!=self.binding['vtable'] or a!=self.scratch+0x6000:raise ValueError('CharacterList request send binding')
            self.events.append(dict(action='send_capture',vtable=vptr,packet_byte_a=int.from_bytes(uc.mem_read(b+0xa,1),'little')))
        elif address==0x141421150:uc.mem_write(a,bytes(16));result=a
        elif address in (0x1413fe190,0x14147d580):pass
        elif address==0x1456b2340:self.events.append(dict(action='packet_cleanup_capture'))
        else:self.events.append(dict(action='helper_capture',address=address,
            this_offset=a-self.object if self.object<=a<self.object+0x400 else None,raw_second=b & 0xffffffff))
        uc.reg_write(x.UC_X86_REG_RAX,result)
        sp=uc.reg_read(x.UC_X86_REG_RSP);ret=int.from_bytes(uc.mem_read(sp,8),'little')
        uc.reg_write(x.UC_X86_REG_RSP,sp+8);uc.reg_write(x.UC_X86_REG_RIP,ret)

    def run(self,address,rcx=0,rdx=0):
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000
        self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,rcx),(x.UC_X86_REG_RDX,rdx)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(address,stop,count=100000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('Character boundary instruction budget')
        return self.uc.reg_read(x.UC_X86_REG_RAX)

    def reset_case(self,level,capacity):
        self.heap=self.scratch+0x10000;self.events=[];self.object=self.scratch+0x1000
        self.uc.mem_write(self.object,b'\xa5'*0x400)
        self.run(INIT,self.object)
        singleton=int.from_bytes(self.uc.mem_read(GLOBAL,8),'little')
        table=int.from_bytes(self.uc.mem_read(self.object,8),'little')
        if singleton!=self.object or table!=TABLE or self.run(0x146486a50)!=self.object:
            raise ValueError('Actual singleton constructor/getter mismatch')
        initial_events=self.events;self.events=[]
        for offset in (0xf0,0x140,0x190,0x210,0x260,0x2b0,0x300):
            self.uc.mem_write(self.object+offset,struct.pack('<I',level))
        for offset in (0x244,0x294,0x2e4):self.uc.mem_write(self.object+offset,struct.pack('<I',capacity))
        self.uc.mem_write(self.object+0x308,b'\xff\xff')
        self.uc.mem_write(0x14b57ecd1,b'\x01')
        self.run(RESET,self.object)
        values={hex(o):int.from_bytes(self.uc.mem_read(self.object+o,4),'little') for o in
            (0xf0,0x140,0x190,0x1a0,0x1b0,0x210,0x220,0x240,0x244,0x248,0x24c,
             0x260,0x270,0x290,0x294,0x298,0x29c,0x2b0,0x2c0,0x2e0,0x2e4,0x2e8,0x2ec,0x300,0x338,0x33c)}
        return dict(level=level,capacity=capacity,constructor_events=initial_events,events=self.events,
            values=values,singleton_matches=True,derived_vtable=table,
            field308=int.from_bytes(self.uc.mem_read(self.object+0x308,2),'little'),
            global_flag=int.from_bytes(self.uc.mem_read(0x14b57ecd1,1),'little'))

    def request_case(self,address):
        self.events=[];self.heap=self.scratch+0x10000;self.object=self.scratch+0x1000
        wrapper,table=self.scratch+0x6000,self.scratch+0x7000
        self.uc.mem_write(wrapper,struct.pack('<Q',table));self.uc.mem_write(table+0x38,struct.pack('<Q',SEND))
        self.uc.mem_write(0x14b520d90,struct.pack('<Q',wrapper))
        self.run(address)
        events=self.events.copy()
        packet,archive=self.scratch+0x2000,self.scratch+0x4000
        self.run(self.binding['constructor'],packet)
        packet_id=self.run(self.binding['id_getter'],packet)
        self.uc.mem_write(archive,b'\xa5'*128)
        before=bytes(self.uc.mem_read(archive,128))
        success=self.run(self.binding['writer'],packet,archive) & 255
        if success!=1 or before!=bytes(self.uc.mem_read(archive,128)) or packet_id!=101:
            raise ValueError('CharacterList empty writer behavior mismatch')
        return dict(address=address,events=events,packet_id=packet_id,writer_returned=success,archive_unchanged=True)


def build():
    upstream=native.ROOT/'code-clues/login-result-handler-replay.json';prior=json.loads(upstream.read_text('utf-8'))
    em=Emulator()
    if prior['sha256']!=em.bindings['sha256']:raise ValueError('Character boundary source mismatch')
    anchors=[]
    for a,size in ((TABLE,0x30),(em.binding['vtable'],0x40),(0x14961a380,4)):
        off=em.image.offset(a-em.image.pe.base);data=em.raw[off:off+size]
        anchors.append(dict(address=a,file_offset=off,bytes=data.hex()))
    if struct.unpack_from('<Q',bytes.fromhex(anchors[0]['bytes']),0x28)[0]!=RESET:
        raise ValueError('Continuation virtual slot mismatch')
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(upstream.read_bytes()).hexdigest(),
        fragments=em.extra,leaves=em.native_leaves,anchors=anchors,packet_binding=em.binding,
        resets=[em.reset_case(level,cap) for level in (0,1,2,5) for cap in (128,256)],
        requests=[em.request_case(a) for a in REQUESTS],native_execution=True,network_ready=False,
        limitations=['Actual singleton constructor/getter/virtual28 reset and two independent request routines execute.',
            'Container init/clear/shrink, diagnostics, cleanup and request send are captures; no real backend objects or network.',
            'Reset and request tests are independent; no proven edge from LoginResult continuation to CharacterList request.',
            'Empty writer leaf/ID101 execute; full frame/send/socket/CharacterList response not executed.',
            'No live singleton/profile/process memory/credentials/game launch/network/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-list-boundary-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),resets=len(report['resets']),requests=len(report['requests']))))
