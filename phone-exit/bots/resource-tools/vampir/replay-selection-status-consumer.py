"""Execute a status consumer and a separate lifecycle transition, without IO."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('status_consumer_base',HERE/'replay-selection-status.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
REQUEST,BASE78,INITIALIZE,CLEAR=0x145d7b850,0x14560d7b0,0x145608fb0,0x145601570


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        manifest=json.loads((native.ROOT/'ghidra/entry-manifest.json').read_text('utf-8'))
        names={'SelectionStatus_GatedRequest','SelectionStatus_RequestConstruct',
            'SelectionStatus_BaseInitialize','SelectionStatus_BaseClear','SelectionLifecycle_Base78'}
        functions=[f for f in manifest['functions'] if f['name'] in names]
        if len(functions)!=len(names):raise ValueError('Incomplete consumer sources')
        self.consumer_ranges=[r for f in functions for r in f['ranges']]
        for r in self.consumer_ranges:
            lo,hi=int(r['start'],16),int(r['end_exclusive'],16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset']+hi-lo]).hexdigest()!=r['sha256']:
                raise ValueError('Consumer source range changed')
            self.ranges.append((lo,hi))
            for page in range(lo & ~4095,(hi+4095)&~4095,4096):self.map_source_page(page)
        self.consumer_hooks={0x144aa7c40,0x144aa8020,0x1456b2340,0x145552630,
            0x1454894b0,0x143c15a20,0x143c0fe10,0x145692ec0,0x1445cbd50,
            0x1454de430,0x1414400e0,0x144a781f0,0x144aaa9d0,0x144aab350,0x14558ee20}
        for a in (*self.consumer_hooks,0x14b27eecb):self.map_source_page(a & ~4095)

    def hook(self,uc,address,size,user):
        if self.handler_phase and address in self.consumer_hooks:
            a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
            ctx=self.context;result=0
            if address in (0x144aa7c40,0x144aaa9d0):result=ctx+0x14000
            elif address in (0x1454894b0,0x143c15a20,0x1454de430):result=ctx+0x15000
            elif address==0x14558ee20:result=ctx+0x16000
            elif address==0x144aa8020:
                if a!=ctx+0x14000 or c!=0x13f:raise ValueError('Unexpected request handoff')
                sp=uc.reg_read(x.UC_X86_REG_RSP)
                self.events.append(dict(action='request_handoff_capture',kind=c,
                    packet_vtable=int.from_bytes(uc.mem_read(b,8),'little'),
                    packet_flag_a=uc.mem_read(b+0xa,1)[0],
                    raw10=int.from_bytes(uc.mem_read(b+0x10,4),'little'),
                    timeout_hex=bytes(uc.mem_read(sp+0x28,4)).hex(),opaque=d))
            elif address in (0x145692ec0,0x1414400e0,0x144aab350):
                self.events.append(dict(action='lifecycle_backend_capture',address=address))
            # Other boundaries select absent world/UI objects, no auxiliary
            # mode, and cleanup captures. Application branches remain native.
            self.finish(result);return
        return super().hook(uc,address,size,user)

    def call_source(self,address,argument=0):
        self.handler_phase=True;ctx=self.context
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000
        self.uc.mem_write(stack,struct.pack('<Q',stop));self.uc.mem_write(stack+0x28,bytes(8))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,ctx+0x5000),
            (x.UC_X86_REG_RDX,argument),(x.UC_X86_REG_R8,0),(x.UC_X86_REG_R9,0)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(address,stop,count=100000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('Consumer instruction budget')

    def setup_consumer(self,status):
        self.handler_phase=True;ctx=self.context;self.events=[]
        self.uc.mem_write(ctx,bytes(0x20000));self.uc.mem_write(ctx+0x5030,bytes([status]))
        self.uc.mem_write(0x14b574a90,struct.pack('<Q',ctx+0x5000))
        self.uc.mem_write(0x14b27eecb,bytes(1))
        self.uc.mem_write(ctx+0x16008,struct.pack('<Q',0x1122334455667788))
        self.uc.mem_write(ctx+0x16024,struct.pack('<I',17))


def build():
    em=Emulator();matrix=[]
    for status in range(256):
        em.setup_consumer(status);em.call_source(REQUEST,0x89abcdef)
        sends=[e for e in em.events if e['action']=='request_handoff_capture']
        if len(sends)!=int(status>=6):raise ValueError('Unsigned status gate mismatch')
        if sends and (sends[0]['raw10']!=0x89abcdef or sends[0]['timeout_hex']!='00000000'):
            raise ValueError('Request raw field/timeout mismatch')
        matrix.append(dict(status=status,events=em.events.copy()))
    leaves=[]
    for prior in (0,1,6,7,255):
        em.setup_consumer(prior);ctx=em.context
        em.uc.mem_write(ctx+0x5078,b'\xa5\xa5');em.uc.mem_write(ctx+0x50c8,b'\xa5'*16)
        em.call_source(CLEAR)
        clear_status=em.uc.mem_read(ctx+0x5030,1)[0]
        if clear_status!=prior or bytes(em.uc.mem_read(ctx+0x5078,2))!=b'\0\1' or bytes(em.uc.mem_read(ctx+0x50c8,16))!=bytes(16):
            raise ValueError('Clear preserved status/reset fields mismatch')
        em.call_source(INITIALIZE)
        if em.uc.mem_read(ctx+0x5030,1)[0]!=7:raise ValueError('Initialize status mismatch')
        leaves.append(dict(prior=prior,after_clear=clear_status,after_initialize=7))
    transitions=[]
    fixture=dict(gate_state=0,metadata=False,platform=False,ui_present=False,ui_same=False,service_flag=0,code=0)
    for raw in (0,1,0xffffffff):
        em.setup_consumer(0)
        response=em.execute(base.base.base.profile_body('',0),fixture)
        ctx=em.context;after_response=em.uc.mem_read(ctx+0x5030,1)[0]
        em.uc.mem_write(ctx+0x16008,struct.pack('<Q',0x1122334455667788))
        em.uc.mem_write(ctx+0x16024,struct.pack('<I',17))
        em.events=[];em.call_source(REQUEST,raw);before_events=em.events.copy()
        if before_events:raise ValueError('Status 1 request should return before handoff')
        em.call_source(BASE78);after_lifecycle=em.uc.mem_read(ctx+0x5030,1)[0]
        lifecycle_events=em.events.copy();em.events=[]
        em.call_source(REQUEST,raw);after_events=em.events.copy()
        if (after_response,after_lifecycle)!=(1,6):raise ValueError('Selection/lifecycle status sequence mismatch')
        sends=[e for e in after_events if e['action']=='request_handoff_capture']
        if len(sends)!=1 or sends[0]['raw10']!=raw:raise ValueError('Status 6 request mismatch')
        flags=int.from_bytes(em.uc.mem_read(ctx+0x16008,8),'little')
        depth=int.from_bytes(em.uc.mem_read(ctx+0x16024,4),'little')
        if flags!=0x1122334455667688 or depth!=17:raise ValueError('Lifecycle flag/listener depth mismatch')
        transitions.append(dict(raw=raw,response=response,after_response=after_response,before_events=before_events,
            after_lifecycle=after_lifecycle,lifecycle_events=lifecycle_events,after_events=after_events,flags=flags,depth=depth))
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-selection-status.py','replay-character-select-handler.py')},
        consumer_ranges=em.consumer_ranges,matrix=matrix,leaves=leaves,transitions=transitions,
        native_execution=True,network_ready=False,
        limitations=['Status guard, request constructor, base lifecycle method and status setter execute; actual ID110 pipeline precedes separate explicit lifecycle invocation.',
            'Lifecycle caller/engine event and transition timing are not proved; no automatic transition from ID110 to Base78 is asserted.',
            'World/UI lookups absent, service callbacks/listeners empty, auxiliary mode false; backend/diagnostic/cleanup/handoff captures, no socket IO.',
            'Handoff kind 319 is not the packet ID; raw request argument semantics unknown. Status >=6 includes initialized value 7, so is not session readiness.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/selection-status-consumer-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        matrix=len(report['matrix']),transitions=len(report['transitions']))))
