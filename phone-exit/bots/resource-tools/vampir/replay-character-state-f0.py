"""Execute ID102 -> actual rawF0 setter, then independent setter branch cases."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('state_f0_base',HERE/'replay-character-list-handler.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
SETTER=0x145c930d0


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.setter_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(SETTER)]})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.setter_fragments)
        self.setter_hooks={0x145c860c0,0x1445d0530}
        refs=[a for f in self.setter_fragments for r in f['instructions'] for a in r['rip_references']]
        pages={p for lo,hi in self.ranges for p in range(lo & ~4095,(hi+4095)&~4095,4096)}
        pages.update(a & ~4095 for a in (*refs,*self.setter_hooks))
        pages.update((a & ~4095)+4096 for a in self.setter_hooks)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])

    def hook(self,uc,address,size,user):
        if self.handler_phase and address==SETTER:
            self.events.append(dict(action='native_setter_entry',value=uc.reg_read(x.UC_X86_REG_RDX)))
            # Skip the older handler's explicit capture and execute the setter.
            return base.base.Emulator.hook(self,uc,address,size,user)
        if self.handler_phase and address in self.setter_hooks:
            a,b,c=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
            if address==0x145c860c0:
                if a!=self.context+0x1000:raise ValueError('Setter state receiver changed')
                uc.mem_write(b,bytes(16));result=b
            else:
                result=0;self.events.append(dict(action='persistence_capture'))
            self.finish(result);return
        super().hook(uc,address,size,user)

    def execute(self,body,fixture):
        result=super().execute(body,fixture)
        result['state_raw_f0']=int.from_bytes(self.uc.mem_read(self.context+0x10f0,8),'little')
        return result

    def setter_case(self,old,new):
        self.handler_phase=True;self.events=[];state=self.context+0x1000
        self.uc.mem_write(state,bytes(0x200));self.uc.mem_write(state+0xf0,struct.pack('<Q',old))
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000
        self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,state),(x.UC_X86_REG_RDX,new)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(SETTER,stop,count=100000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('Setter instruction budget')
        return dict(old=old,new=new,actual=int.from_bytes(self.uc.mem_read(state+0xf0,8),'little'),events=self.events.copy())


def build():
    em=Emulator();upstream=native.ROOT/'code-clues/character-list-handler-replay.json'
    prior=json.loads(upstream.read_text('utf-8'))
    cases=[em.execute(bytes.fromhex(c['decoded']['payload_hex']),c['fixture']) for c in prior['cases']]
    for c in cases:
        applied=any(e['action']=='selection_event_capture' for e in c['events'])
        if c['state_raw_f0']!=(c['decoded']['tail'][3] if applied else 0):raise ValueError('Native ID102 -> state_f0 mismatch')
    setters=[em.setter_case(old,new) for old in (0,1,2**64-1) for new in (0,1,0x0102030405060708,2**64-1)]
    if any(c['actual']!=c['new'] or sum(e['action']=='persistence_capture' for e in c['events'])!=int(c['old']!=0 and c['old']!=c['new']) for c in setters):
        raise ValueError('Native setter value/persistence gates mismatch')
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(upstream.read_bytes()).hexdigest(),
        dependency_sha256=hashlib.sha256((HERE/'replay-character-list-handler.py').read_bytes()).hexdigest(),
        fragments=em.setter_fragments,cases=cases,setters=setters,native_execution=True,network_ready=False,
        limitations=['Actual full ID102 body/handler now executes setter0x145c930d0; source of raw state_f0 is packet+40 on covered accepted paths.',
            'Persistence/path/log helpers and inherited state/UI/transport/container backends are fixtures/captures.',
            'Additional UI action caller exported statically only; no semantic name or actual runtime lifetime inferred.',
            'No real server/profile/session/socket/ID110/game process/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-state-f0-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']),setters=len(report['setters']))))
