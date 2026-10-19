"""Whole ID102 body -> native result gate/predicate/handler with backend captures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('list_handler_base',HERE/'replay-character-list-extensions.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
HANDLER,GATE,PREDICATE=0x14675dce0,0x1467a8e10,0x145c85d90
EXIT,POLICY,OWNER_NEXT=0x30009000,0x30009010,0x30009020


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__();self.handler_phase=False
        addresses=(HANDLER,PREDICATE)
        self.handler_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in addresses})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.handler_fragments)
        root=self.image.roots[self.image.containing(GATE)]
        self.gate_ranges=[];self.gate_trace={}
        for begin,end,unwind in self.image.ranges:
            if self.image.roots[(begin,end,unwind)]!=root:continue
            off=self.image.offset(begin);data=self.raw[off:off+end-begin]
            self.gate_ranges.append(dict(begin=self.image.pe.base+begin,end=self.image.pe.base+end,
                file_offset=off,sha256=hashlib.sha256(data).hexdigest()))
            self.ranges.append((self.image.pe.base+begin,self.image.pe.base+end))
        binding=next(p for p in self.bindings['packets'] if p['name']=='PktCharacterListReadResult')
        self.handler_leaves=[]
        for address,size in ((binding['id_getter'],6),(0x1456048e0,8),(0x144aaa9d0,8)):
            off=self.image.offset(address-self.image.pe.base)
            self.handler_leaves.append(dict(address=address,file_offset=off,bytes=self.raw[off:off+size].hex()))
            self.ranges.append((address,address+size))
        self.handler_hooks={0x14142d840,0x141424430,0x14147d580,0x141421150,0x1413fe190,
            0x14558edf0,0x145f8a7a0,0x145c859f0,0x1456d32e0,0x1456e4040,0x1456d29f0,
            0x145c930d0,0x14563d980,0x145636eb0,0x1463e0580,0x145c92a50,
            0x1445cbdd0,0x145467510,0x144a71e10,0x141420f70,0x1456140f0,0x144aab350,
            0x1445cbd50,0x1454f2ba0,EXIT,POLICY,OWNER_NEXT}
        rows=[r for f in self.handler_fragments for r in f['instructions']]
        call=next(r for r in rows if r.get('direct_target')==GATE)
        self.gate_return=call['address']+len(bytes.fromhex(call['bytes']))
        pages={p for lo,hi in self.ranges for p in range(lo & ~4095,(hi+4095)&~4095,4096)}
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        pages.update(a & ~4095 for a in (*self.handler_hooks,0x14b574a90,0x14b520d90,0x14b27eecb,0x149d81368))
        pages.update((a & ~4095)+4096 for a in self.handler_hooks if a>0x140000000)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])
        self.context=0x23000000;self.uc.mem_map(self.context,0x10000)

    def hook(self,uc,address,size,user):
        if not self.handler_phase:return super().hook(uc,address,size,user)
        if address==GATE:self.events.append(dict(action='native_gate',code=uc.reg_read(x.UC_X86_REG_ECX),packet_id=uc.reg_read(x.UC_X86_REG_EDX)))
        if address==self.gate_return:self.events.append(dict(action='native_gate_return',value=uc.reg_read(x.UC_X86_REG_AL)))
        if any(r['begin']<=address<r['end'] for r in self.gate_ranges):
            cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
            data=bytes(uc.mem_read(address,size));rows=list(cs.disasm(data,address))
            if len(rows)!=1 or rows[0].size!=size:raise ValueError('Gate executed instruction decode')
            i=rows[0];refs=[i.address+i.size+op.mem.disp for op in i.operands
                if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
            self.gate_trace[address]=dict(address=address,file_offset=self.image.offset(address-self.image.pe.base),
                bytes=data.hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=refs)
            for ref in refs:
                page=ref & ~4095
                if any(lo<=page<=hi for lo,hi,_ in uc.mem_regions()):continue
                uc.mem_map(page,4096);off=self.image.offset(page-self.image.pe.base);uc.mem_write(page,self.raw[off:off+4096])
        if address not in self.handler_hooks:return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        ctx=self.context;result=0
        if address in (0x14142d840,0x141421150,0x141420f70):uc.mem_write(a,bytes(16));result=a
        elif address in (0x141424430,0x14147d580,0x1413fe190):pass
        elif address==0x14558edf0:result=ctx+0x6000
        elif address==0x145f8a7a0:self.events.append(dict(action='gate_error_capture',code=a & 0xffffffff))
        elif address==0x145c859f0:result=ctx+0x1000
        elif address==0x1456d32e0:self.events.append(dict(action='old_list_cleanup_capture',count=b))
        elif address==0x1456e4040:
            if a!=ctx+0x1070 or b>4:raise ValueError('State list capacity fixture bound')
            pointer=self.alloc(b*0x170) if b else 0
            uc.mem_write(a,struct.pack('<Q',pointer));uc.mem_write(a+12,struct.pack('<I',b))
        elif address==0x1456d29f0:
            if c>4:raise ValueError('State list copy fixture bound')
            if c:uc.mem_write(a,bytes(uc.mem_read(b,c*0x170)))
            self.events.append(dict(action='list_copy_capture',count=c))
        elif address==0x145c930d0:self.events.append(dict(action='state_tail40_capture',raw64=b))
        elif address==0x14563d980:result=ctx+0x7000
        elif address==0x145636eb0:self.events.append(dict(action='negative_tail28_warning_capture'))
        elif address==0x1463e0580:result=ctx+0x3000 if self.fixture['ui_present'] else 0
        elif address==0x145c92a50:self.events.append(dict(action='selection_ui_reset_capture'))
        elif address==0x1445cbdd0:result=0
        elif address==0x145467510:result=ctx+0x4000 if self.fixture['owner_present'] else 0
        elif address==0x144a71e10:self.events.append(dict(action='ui_finish_capture'))
        elif address==0x1456140f0:self.events.append(dict(action='selection_event_capture',event=b & 255))
        elif address==0x144aab350:self.events.append(dict(action='transport_flag_capture',value=b))
        elif address==0x1445cbd50:result=ctx+0x8000 if self.fixture['policy_present'] else 0
        elif address==0x1454f2ba0:result=ctx+0xa000
        elif address==POLICY:result=self.fixture['policy'];self.events.append(dict(action='policy_virtual_capture',value=result))
        elif address==EXIT:self.events.append(dict(action='selection_exit_capture'))
        elif address==OWNER_NEXT:self.events.append(dict(action='owner_a00_capture'))
        self.finish(result)

    def execute(self,body,fixture):
        self.handler_phase=False;decoded=self.read_list(body)
        if decoded['returned']!=1:raise ValueError('Complete body required before handler')
        self.fixture=fixture;self.events=[];ctx=self.context
        self.uc.mem_write(ctx,bytes(0x10000))
        self.uc.mem_write(ctx+0x5000,struct.pack('<Q',ctx+0x5100))
        self.uc.mem_write(ctx+0x5138,struct.pack('<Q',EXIT))
        self.uc.mem_write(ctx+0x4000,struct.pack('<Q',ctx+0x4200))
        self.uc.mem_write(ctx+0x4c00,struct.pack('<Q',OWNER_NEXT))
        self.uc.mem_write(0x14b574a90,struct.pack('<Q',ctx+0x5000))
        self.uc.mem_write(0x14b520d90,struct.pack('<Q',ctx+0xb000))
        self.uc.mem_write(0x14b27eecb,bytes([fixture['policy_disabled']]))
        self.uc.mem_write(ctx+0x6008,bytes([fixture['gate_state']]))
        # Source-bound predicate with synthetic type metadata and policy virtual.
        self.uc.mem_write(ctx+0x8000,struct.pack('<Q',ctx+0x9000))
        self.uc.mem_write(ctx+0x8010,struct.pack('<Q',ctx+0xa200))
        self.uc.mem_write(ctx+0xa230,struct.pack('<Q',ctx+0xa400))
        self.uc.mem_write(ctx+0xa238,struct.pack('<i',1));self.uc.mem_write(ctx+0xa038,struct.pack('<i',1))
        self.uc.mem_write(ctx+0xa408,struct.pack('<Q',ctx+0xa030))
        self.uc.mem_write(ctx+0x9a18,struct.pack('<Q',POLICY))
        self.uc.mem_write(ctx+0x33f8,struct.pack('<i',-9))
        self.handler_phase=True
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000
        self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,ctx),(x.UC_X86_REG_RDX,0x12345678),(x.UC_X86_REG_R8,self.scratch+0x1000)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(HANDLER,stop,count=250000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('List handler budget')
        p,n=struct.unpack('<QI',bytes(self.uc.mem_read(ctx+0x1070,12)))
        if n>4:raise ValueError('State output count bound')
        return dict(fixture=fixture,decoded=decoded,events=self.events.copy(),state=dict(count=n,
            raw80=int.from_bytes(self.uc.mem_read(ctx+0x1080,4),'little'),
            raw84=int.from_bytes(self.uc.mem_read(ctx+0x1084,4),'little'),
            record_raw8=[int.from_bytes(self.uc.mem_read(p+i*0x170+8,8),'little') for i in range(n)]),
            selected_index=struct.unpack('<i',bytes(self.uc.mem_read(ctx+0x33f8,4)))[0] if fixture['ui_present'] else None)


def build():
    em=Emulator();off=em.image.offset(0x14961a378-em.image.pe.base);sentinel=struct.unpack_from('<Q',em.raw,off)[0]
    default=dict(gate_state=0,policy_disabled=False,policy_present=True,policy=1,ui_present=True,owner_present=True)
    cases=[]
    def body(ids,preferred,code=0,raw28=0x8000000000000001):
        return struct.pack('<IIH',code,207,len(ids))+b''.join(base.base.record_bytes(value=v) for v in ids)+struct.pack('<QIQQ',raw28,23,preferred,0x123456789abcdef)
    for ids in ((),(11,),(11,22,33),(11,22,22,33),(11,0,22)):
        for preferred in (sentinel,11,22,33,99):
            cases.append(em.execute(body(ids,preferred),dict(default,name='count-'+str(len(ids))+'-preferred-'+str(preferred))))
    for update in (dict(name='policy-zero',policy=0),dict(name='policy-two',policy=2),dict(name='policy-four',policy=4),
            dict(name='policy-disabled',policy_disabled=True),dict(name='policy-absent',policy_present=False),
            dict(name='ui-absent',ui_present=False),dict(name='owner-absent',owner_present=False),dict(name='gate-state1',gate_state=1)):
        cases.append(em.execute(body((11,22,33),22),dict(default,**update)))
    for code in (1,14,22,37,54,9400,9818,9819,90021,0xffffffff):
        cases.append(em.execute(body((11,22),22,code=code),dict(default,name='code-'+str(code))))
    cases.append(em.execute(body((11,22),22,raw28=7),dict(default,name='positive-tail28')))
    extension_body=base.list_bytes(((0xffffffff,255,65535),),base.optional_bytes(((1,255,2,3,4,5),(1,1,6,7,8,9))),count=2)
    cases.append(em.execute(extension_body,dict(default,name='with-nested-extensions')))
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),fragments=em.handler_fragments,
        upstream_sha256=hashlib.sha256((native.ROOT/'code-clues/character-list-extensions-replay.json').read_bytes()).hexdigest(),
        dependency_sha256={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-character-list-extensions.py','replay-character-list-reader.py','replay-login-result-reader.py')},
        gate_ranges=em.gate_ranges,gate_trace=[em.gate_trace[a] for a in sorted(em.gate_trace)],leaves=em.handler_leaves,
        sentinel=sentinel,cases=cases,native_execution=True,network_ready=False,
        limitations=['Actual full body/records/extensions then handler/result gate and selection predicate execute in the same emulator.',
            'Source-bound predicate reads synthetic type metadata/policy virtual; no real engine lifecycle.',
            'Diagnostics/getters, state list capacity/shallow copy/cleanup, UI callbacks/owner virtual/event and transport setter are explicit fixtures/captures.',
            'Only covered result codes/gate-state branches; other branches fail on unreviewed native targets.',
            'No dispatch/socket/live session/real character choice/game process/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-list-handler-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
