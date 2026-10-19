"""Actual caller -> singleton -> slot90 -> CharacterListRead send capture."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('request_caller_base',HERE/'replay-selection-service.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
CALLER=0x1468f1d70
POLICY,POST2,STATE98=0x30007000,0x30007010,0x30007020


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.caller_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(CALLER)]})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.caller_fragments)
        self.caller_hooks={0x145516a30,0x1468f3dd0,0x144a21450,0x1445cc1e0,0x14563d9a0,
            0x145646f00,0x145c95430,0x1455b8220,0x1455c5260,POLICY,POST2,STATE98}
        refs=[a for f in self.caller_fragments for r in f['instructions'] for a in r['rip_references']]
        pages={p for lo,hi in self.ranges for p in range(lo & ~4095,(hi+4095)&~4095,4096)}
        pages.update(a & ~4095 for a in (*refs,*self.caller_hooks))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])
        self.ctx=0x24000000;self.uc.mem_map(self.ctx,0x10000)

    def hook(self,uc,address,size,user):
        if address not in self.caller_hooks:return super().hook(uc,address,size,user)
        a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
        result=0
        if address==POLICY:
            if a!=self.ctx:raise ValueError('Policy receiver changed')
            result=self.policy[self.policy_index];self.policy_index+=1
            self.events.append(dict(action='policy_virtual_capture',value=result))
        elif address==POST2:self.events.append(dict(action='owner_virtual_a00_capture'))
        elif address==STATE98:
            if a!=self.service:raise ValueError('State98 receiver changed')
            self.events.append(dict(action='service_virtual98_capture'))
        elif address==0x144a21450:result=self.ctx+0x2000
        elif address in (0x14563d9a0,0x1455b8220):result=self.ctx+0x3000
        else:self.events.append(dict(action='caller_helper_capture',address=address))
        self.finish(result)

    def execute(self,first,second,disabled):
        self.initialize();self.object=self.service;self.events=[]
        self.policy=(first,second);self.policy_index=0
        self.uc.mem_write(self.ctx,bytes(0x10000))
        self.uc.mem_write(self.ctx,struct.pack('<Q',self.ctx+0x1000))
        self.uc.mem_write(self.ctx+0x1a18,struct.pack('<Q',POLICY))
        self.uc.mem_write(self.ctx+0x1a00,struct.pack('<Q',POST2))
        # Actual derived slots remain intact except independent state98 backend capture.
        table=bytes(self.uc.mem_read(base.TABLE,0xd8));self.uc.mem_write(self.ctx+0x4000,table)
        self.uc.mem_write(self.ctx+0x4098,struct.pack('<Q',STATE98))
        self.uc.mem_write(self.service,struct.pack('<Q',self.ctx+0x4000))
        wrapper,table=self.scratch+0x6000,self.scratch+0x7000
        self.uc.mem_write(wrapper,struct.pack('<Q',table))
        self.uc.mem_write(table+0x38,struct.pack('<Q',base.base.SEND))
        self.uc.mem_write(0x14b520d90,struct.pack('<Q',wrapper))
        self.uc.mem_write(0x14b27eecb,bytes([disabled]))
        self.uc.mem_write(0x14b144a68,b'\0')
        self.uc.mem_write(0x14b571319,b'\0')
        self.run(CALLER,self.ctx)
        if self.policy_index!=2:raise ValueError('Expected two independent policy reads')
        return dict(first=first,second=second,lookup_disabled=disabled,events=self.events.copy(),
            field260=int.from_bytes(self.uc.mem_read(self.ctx+0x2260,1),'little'),
            flags=[int.from_bytes(self.uc.mem_read(a,1),'little') for a in (0x14b144a68,0x14b571319)])


def build():
    em=Emulator()
    path=native.ROOT/'code-clues/selection-service-callers.json'
    scan=json.loads(path.read_text('utf-8'))
    if scan['sha256']!=em.bindings['sha256']:raise ValueError('Caller scan source mismatch')
    return dict(schema_version=1,source=scan['source'],sha256=scan['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        scan_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),fragments=em.caller_fragments,
        cases=[em.execute(a,b,d) for a in (0,1,2,4) for b in (0,1,2,4) for d in (0,1)],
        native_execution=True,network_ready=False,
        limitations=['Actual caller, singleton getter, derived slot90 RequestA, packet constructor and send dispatch execute.',
            'Owner object/policy virtual, state98, owner a00, UI helpers and send target are explicit fixtures/captures.',
            'Lookup enabled branch uses null lookup fixture; nonnull type-check branch not covered.',
            'No caller owner class/lifecycle binding, real level completion, packet frame/socket/response102/live session/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-list-caller-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
