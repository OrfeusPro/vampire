"""Native engine candidate -> constructed owner -> service finish path."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('engine_owner_base',HERE/'replay-world-finish-owner.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
ENTRY=0x14430da70
OTHER=0x3000f0a0


class Emulator(base.Emulator):
    def __init__(self):
        self.suppress_owner=False
        super().__init__()
        manifest=json.loads((native.ROOT/'ghidra/entry-manifest.json').read_text('utf-8'))
        self.dispatch_ranges=[r for f in manifest['functions'] if f['name']=='OwnerDispatch_CandidateC' for r in f['ranges']]
        if not self.dispatch_ranges:raise ValueError('Missing engine dispatch source')
        for r in self.dispatch_ranges:
            lo,hi=int(r['start'],16),int(r['end_exclusive'],16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset']+hi-lo]).hexdigest()!=r['sha256']:
                raise ValueError('Engine dispatch source changed')
            self.ranges.append((lo,hi))
            for page in range(lo & ~4095,(hi+4095)&~4095,4096):self.map_source_page(page)
        self.engine_hooks={0x144262710,0x143d9cec0,0x14431dbc0,OTHER}
        for a in self.engine_hooks:self.map_source_page(a & ~4095)

    def call_owner(self,address,receiver):
        if self.suppress_owner and address==base.CALLER:return
        return super().call_owner(address,receiver)

    def hook(self,uc,address,size,user):
        if address==ENTRY:self.events.append(dict(action='native_engine_dispatch'))
        if address==base.CALLER:
            receiver=uc.reg_read(x.UC_X86_REG_RCX)
            if receiver!=self.context+0x19000:raise ValueError('Engine dispatch owner receiver mismatch')
            self.events.append(dict(action='engine_owner_receiver',receiver=receiver))
        if address in self.engine_hooks:
            if address==0x144262710:
                a,b,c=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
                if a!=self.context+0x10848 or b:raise ValueError('Engine delegate boundary mismatch')
                callback=int.from_bytes(uc.mem_read(c,8),'little')
                if callback!=0x143963850:raise ValueError('Engine callback descriptor changed')
                self.events.append(dict(action='engine_iteration_capture',callback=callback))
            elif address==OTHER:self.events.append(dict(action='secondary_virtual_capture'))
            else:self.events.append(dict(action='engine_cached_flag_capture',address=address))
            self.finish(0);return
        return super().hook(uc,address,size,user)

    def execute_dispatch(self,ctor,table,status,owner_present=True,secondary=False,world_kind=7,cached=1):
        self.suppress_owner=True
        self.execute_owner(ctor,table,status)
        self.suppress_owner=False;self.events=[];ctx=self.context;engine=ctx+0x10000
        self.uc.mem_write(engine,bytes(0x1000));self.uc.mem_write(engine+0x13a,bytes([world_kind]))
        self.uc.mem_write(engine+0xd9,bytes([cached]))
        self.uc.mem_write(engine+0x158,struct.pack('<Q',ctx+0x19000 if owner_present else 0))
        self.uc.mem_write(engine+0x168,struct.pack('<Q',ctx+0x1e000 if secondary else 0))
        self.uc.mem_write(ctx+0x1e000,struct.pack('<Q',ctx+0x1e800))
        self.uc.mem_write(ctx+0x1eae8,struct.pack('<Q',OTHER))
        self.call_owner(ENTRY,engine)
        return dict(constructor=ctor,table=table,status=status,owner_present=owner_present,secondary=secondary,
            world_kind=world_kind,cached=cached,events=self.events.copy(),state=dict(
                status30=self.uc.mem_read(ctx+0x5030,1)[0],
                owner_handle=int.from_bytes(self.uc.mem_read(ctx+0x193e0,8),'little'),
                cached_d9=self.uc.mem_read(engine+0xd9,1)[0]))


def build():
    em=Emulator();cases=[]
    for ctor,table in base.OWNERS:
        for status in (1,2,4):
            for present in (False,True):
                for secondary in (False,True):cases.append(em.execute_dispatch(ctor,table,status,present,secondary))
        for kind in (0,1,6):cases.append(em.execute_dispatch(ctor,table,2,world_kind=kind,cached=0))
    for case in cases:
        calls=[e for e in case['events'] if e['action']=='engine_owner_receiver']
        sends=[e for e in case['events'] if e['action']=='finish_packet_capture']
        expected=case['owner_present'] and case['status'] in (2,3,4)
        if len(calls)!=int(case['owner_present']) or len(sends)!=int(expected):raise ValueError('Native engine-to-owner gate mismatch')
        if case['state']['status30']!=(5 if expected else case['status']):raise ValueError('Engine dispatch status mismatch')
        second=[e for e in case['events'] if e['action']=='secondary_virtual_capture']
        if len(second)!=int(case['owner_present'] and case['secondary']):raise ValueError('Secondary callback must depend on owner presence')
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256=hashlib.sha256((HERE/'replay-world-finish-owner.py').read_bytes()).hexdigest(),
        dispatch_ranges=em.dispatch_ranges,cases=cases,native_execution=True,network_ready=False,
        limitations=['Actual full function14430da70 reads supplied object+158 and invokes actual constructed owner slot7b0, service80/70/guard/ID205 constructor.',
            'Containing engine object, owner assignment to field158, world kind/cache flags and service status are fixtures; real engine lifecycle and dynamic type selection not proved.',
            'Engine iterator/secondary object and cached-flag backends are captures; no assertion that arbitrary matching virtual slots share a receiver type.',
            'No game process, actor movement, queue/socket IO or server session.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/world-owner-dispatch-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
