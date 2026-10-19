"""Native selection service construction prefix and CharacterSelect handoff."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('selection_boundary',HERE/'replay-character-list-boundary.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
INIT,END,GLOBAL,TABLE=0x145dc6b20,0x145dc6bfa,0x14b574a90,0x1499f11f0
SELECT=0x145dc05f0


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.select_binding=next(p for p in self.bindings['packets'] if p['name']=='PktCharacterSelect')
        self.service_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in
            (INIT,0x1455f9ee0,0x145dbba60,SELECT)})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.service_fragments)
        self.service_leaves=[]
        for a,length in ((0x1456048e0,8),(self.select_binding['constructor'],30),(self.select_binding['id_getter'],6)):
            off=self.image.offset(a-self.image.pe.base);data=self.raw[off:off+length]
            self.service_leaves.append(dict(address=a,file_offset=off,bytes=data.hex()))
            self.ranges.append((a,a+length))
        self.service_hooks={0x145610ab0,0x145c859f0,0x144aa7c40,0x144aa8020}
        rows=[r for f in self.service_fragments for r in f['instructions']]
        refs=[a for r in rows for a in r['rip_references']]
        pages={p for begin,end in self.ranges for p in range(begin & ~4095,(end+4095) & ~4095,4096)}
        pages.update(a & ~4095 for a in (*refs,*self.service_hooks,GLOBAL,TABLE,self.select_binding['vtable']))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])
        self.service=self.scratch+0xc000
        self.init_phase=False

    def hook(self,uc,address,size,user):
        if self.init_phase and address==END:
            self.owner_argument=uc.reg_read(x.UC_X86_REG_RCX)
            self.attach_argument=uc.reg_read(x.UC_X86_REG_RDX)
            uc.emu_stop();return
        if self.init_phase and address==0x1468e4100:
            length=uc.reg_read(x.UC_X86_REG_RCX)
            if length!=0x1b0:raise ValueError('Service allocation bound changed')
            result=0 if self.allocate_fail else self.service
            if result:uc.mem_write(result,b'\xa5'*length)
            self.finish(result);return
        if address not in self.service_hooks:return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==0x145610ab0:
            if a!=self.service:raise ValueError('Base selection helper this')
            self.events.append(dict(action='base_selection_capture',raw64=b,raw32=c & 0xffffffff))
        elif address==0x145c859f0:result=self.scratch+0x4000
        elif address==0x144aa7c40:result=self.scratch+0x5000
        elif address==0x144aa8020:
            sp=uc.reg_read(x.UC_X86_REG_RSP)
            if a!=self.scratch+0x5000 or c!=110 or int.from_bytes(uc.mem_read(b,8),'little')!=self.select_binding['vtable']:
                raise ValueError('CharacterSelect handoff binding')
            self.events.append(dict(action='select_handoff_capture',kind=c,opaque_argument=d,
                timeout=struct.unpack('<f',bytes(uc.mem_read(sp+0x28,4)))[0],
                packet_raw10=int.from_bytes(uc.mem_read(b+0x10,8),'little'),
                packet_raw18=int.from_bytes(uc.mem_read(b+0x18,4),'little'),
                packet_raw20=int.from_bytes(uc.mem_read(b+0x20,8),'little')))
        self.finish(result)

    def finish(self,result):
        self.uc.reg_write(x.UC_X86_REG_RAX,result)
        sp=self.uc.reg_read(x.UC_X86_REG_RSP);ret=int.from_bytes(self.uc.mem_read(sp,8),'little')
        self.uc.reg_write(x.UC_X86_REG_RSP,sp+8);self.uc.reg_write(x.UC_X86_REG_RIP,ret)

    def initialize(self,fail=False):
        self.object=self.service;self.events=[];self.heap=self.scratch+0x10000
        self.allocate_fail=fail;self.init_phase=True
        prior_global=self.scratch+0xe000
        self.uc.mem_write(GLOBAL,struct.pack('<Q',prior_global))
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000
        self.uc.mem_write(stack,struct.pack('<Q',stop))
        self.uc.reg_write(x.UC_X86_REG_RSP,stack);self.uc.reg_write(x.UC_X86_REG_RCX,self.scratch+0x8000)
        self.uc.emu_start(INIT,stop,count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=END:raise ValueError('Selection construction prefix budget')
        self.init_phase=False
        global_value=int.from_bytes(self.uc.mem_read(GLOBAL,8),'little')
        self.run(0x1456048e0)
        if self.uc.reg_read(x.UC_X86_REG_RAX)!=global_value:raise ValueError('Service getter mismatch')
        return dict(allocation_failed=fail,global_is_service=global_value==self.service,
            global_preserved=global_value==prior_global,attach_is_service=self.attach_argument==self.service,
            attach_is_null=self.attach_argument==0,owner_offset=self.owner_argument-(self.scratch+0x8000),
            vtable=None if fail else int.from_bytes(self.uc.mem_read(self.service,8),'little'),events=self.events.copy())

    def select_case(self,raw64,raw32,state):
        init=self.initialize()
        self.events=[]
        self.uc.mem_write(self.scratch+0x40f0,struct.pack('<Q',state))
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000
        self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,self.service),
            (x.UC_X86_REG_RDX,raw64),(x.UC_X86_REG_R8,raw32)):self.uc.reg_write(reg,value)
        self.uc.emu_start(SELECT,stop,count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('Selection virtual50 budget')
        return dict(raw64=raw64,raw32=raw32,state_raw_f0=state,initialization=init,events=self.events.copy())


def build():
    path=native.ROOT/'code-clues/waiting-end-character-request-replay.json';prior=json.loads(path.read_text('utf-8'))
    em=Emulator()
    if prior['sha256']!=em.bindings['sha256']:raise ValueError('Selection source mismatch')
    anchors=[]
    for a,size in ((TABLE,0x98),(0x14961a378,8),(0x14961a380,4),(em.select_binding['vtable'],0x40)):
        off=em.image.offset(a-em.image.pe.base);anchors.append(dict(address=a,file_offset=off,bytes=em.raw[off:off+size].hex()))
    table=bytes.fromhex(anchors[0]['bytes'])
    if any(struct.unpack_from('<Q',table,slot)[0]!=target for slot,target in ((0x40,0x145dbba60),(0x50,SELECT),(0x90,0x145dbd4b0))):
        raise ValueError('Selection derived table slots changed')
    cases=[em.select_case(a,b,c) for a,b,c in ((0,0,0),(1,1,1),(0xffffffffffffffff,0xffffffff,0xffffffffffffffff),
        (0x0102030405060708,207,0x8877665544332211))]
    packet_id=em.run(em.select_binding['id_getter'])
    if packet_id!=109:raise ValueError('CharacterSelect ID changed')
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fragments=em.service_fragments,leaves=em.service_leaves,anchors=anchors,packet_binding=em.select_binding,
        packet_id=packet_id,initializations=[em.initialize(False),em.initialize(True)],cases=cases,native_execution=True,network_ready=False,
        limitations=['Actual derived allocation/constructor prefix and base singleton constructor/getter execute until first owner attach call.',
            'Allocator and base member helper fixtures; owner attach and remainder of large construction not executed.',
            'Actual virtual50 creates CharacterSelect and reaches request handoff capture; base selection/state getter/manager/cleanup fixtures.',
            'Derived slots40/90 bound statically; slot40 behavior not executed, independent requestA execution in prior evidence.',
            'Packet ID109 binding from prior index; no writer/frame/socket/response110/selection success/live session/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/selection-service-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
