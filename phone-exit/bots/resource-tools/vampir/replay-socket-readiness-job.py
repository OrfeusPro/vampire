"""Native socket mode job scheduling, one select iteration and completion dispatch."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('readiness_source',HERE/'replay-winsock-error-mapping.py')
wsa=importlib.util.module_from_spec(spec);spec.loader.exec_module(wsa)
connect=wsa.connect
native,x=wsa.native,wsa.x
MODE,RUN,DONE,TABLE=0x1445eab70,0x1445e8080,0x1445e7d80,0x1495042d0
SELECT,FDSET,IOCTL=0x30000300,0x30000310,0x30000320
GETOPT,PREPARE=0x30000330,0x30000340


class Replay(connect.source.resolver.handoff.connect.begin.dispatch.Replay):
    def __init__(self,raw,image,fragments,completion,handle_leaf,fixture):
        super().__init__(raw,image,fragments,dict(bound=False,refcounted=False,execute_ok=False))
        self.fixture=fixture
        rows=[r for f in fragments if f['root_begin_rva']+image.pe.base in (MODE,RUN,0x1445f0c60) for r in f['instructions']]
        rows+=completion['instructions']+handle_leaf['instructions']
        self.allowed={r['address'] for r in rows}
        self.allowed.add(0x14878bc70)
        self.targets={SELECT,FDSET,IOCTL,GETOPT,PREPARE,0x1445da5e0,0x1468e4100,0x1445d90b0,
                      0x1445db8a0,0x1445dad30,0x1445de8b0,0x148796040}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in (*self.targets,TABLE,0x149504668,0x14878bc70))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.uc.mem_write(0x148945a00,struct.pack('<Q',SELECT))
        self.uc.mem_write(0x148945b10,struct.pack('<Q',FDSET))
        self.uc.mem_write(0x148945a58,struct.pack('<Q',IOCTL))
        self.socket,self.engine,self.vtable,self.scheduler=(self.allocate(n) for n in (0x70,16,0x80,16))
        self.uc.mem_write(self.socket+0x38,struct.pack('<I',fixture['handle']))
        self.uc.mem_write(self.socket+0x3c,b'\1')
        self.uc.mem_write(self.engine,struct.pack('<Q',self.vtable))
        for slot,target in ((0x30,0x1445f0c60),(0x50,PREPARE),(0x60,GETOPT)):
            self.uc.mem_write(self.vtable+slot,struct.pack('<Q',target))
        self.uc.mem_write(0x14b4f39d0,struct.pack('<Q',self.engine))
        self.uc.mem_write(0x14b4f39c0,struct.pack('<Q',self.engine))  # Separate prepare-global fixture.
        self.job=None;self.completions=[];self.fd_pointers={};self.worker=False;self.events=[]

    def hook(self,uc,address,size,user):
        if address==0x1445e82d2 and getattr(self,'worker',False):
            self.events.append(dict(action='research_stop_before_next_select'));uc.emu_stop();return
        if address in self.allowed:return
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==IOCTL:
            if a!=self.fixture['handle'] or b!=0x8004667e:raise ValueError('Socket mode ioctl arguments changed')
            value=int.from_bytes(uc.mem_read(c,8),'little')
            self.events.append(dict(action='ioctlsocket_fixture',command=b,value=value,returned=self.fixture['ioctl_return']))
            result=self.fixture['ioctl_return']&0xffffffffffffffff
        elif address==0x1445da5e0:result=self.scheduler
        elif address==0x1468e4100:
            if a!=0x28:raise ValueError('Socket job allocation changed')
            self.job=self.allocate(a);result=self.job
        elif address==0x1445d90b0:uc.mem_write(a,b'\0'*40)
        elif address==0x1445db8a0:
            if a!=self.scheduler or b!=self.job:raise ValueError('Socket job scheduling changed')
            result=int(self.fixture['enqueue_ok'])
            self.events.append(dict(action='socket_job_enqueue_capture',returned=result))
        elif address==PREPARE:
            if b!=1:raise ValueError('Readiness prepare arg changed')
        elif address==SELECT:
            rsp=uc.reg_read(x.UC_X86_REG_RSP)
            timeout_ptr=int.from_bytes(uc.mem_read(rsp+0x28,8),'little')
            tv=list(struct.unpack('<ii',bytes(uc.mem_read(timeout_ptr,8))))
            self.fd_pointers={b:'read',c:'write',d:'exception'}
            counts=[int.from_bytes(uc.mem_read(ptr,4),'little') for ptr in (b,c,d)]
            self.events.append(dict(action='select_fixture',nfds=a,counts=counts,timeout=tv,returned=self.fixture['select_return']))
            result=self.fixture['select_return']&0xffffffffffffffff
        elif address==FDSET:
            which=self.fd_pointers[b]
            result=int(self.fixture[which+'_ready'])
            self.events.append(dict(action='fd_isset_fixture',set=which,returned=result))
        elif address==GETOPT:
            rsp=uc.reg_read(x.UC_X86_REG_RSP)
            out=int.from_bytes(uc.mem_read(rsp+0x28,8),'little');sizeptr=int.from_bytes(uc.mem_read(rsp+0x30,8),'little')
            if c!=0 or d!=1 or int.from_bytes(uc.mem_read(sizeptr,4),'little')!=4:
                raise ValueError('Socket error option arguments changed')
            uc.mem_write(out,struct.pack('<I',self.fixture['option_error']))
            result=int(self.fixture['option_ok'])
            self.events.append(dict(action='socket_error_option_capture',selector=d,value=self.fixture['option_error'],returned=result))
        elif address==0x1445dad30:
            if a!=self.job or c or d:raise ValueError('Readiness completion arguments changed')
            self.completions.append(b)
            self.events.append(dict(action='socket_completion_schedule_capture',code=b))
        elif address==0x1445de8b0:
            if a!=self.socket or c!=self.socket:raise ValueError('Readiness completion owner changed')
            self.events.append(dict(action='socket_notification_dispatch_capture',callback=b))
        elif address==0x148796040:result=uc.reg_read(x.UC_X86_REG_RAX)
        else:raise ValueError('Unexpected readiness instruction '+hex(address))
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        self.run(MODE,self.socket,0)
        mode_result=self.uc.reg_read(x.UC_X86_REG_RAX)&255
        if mode_result:
            self.uc.mem_write(self.socket+0x48,struct.pack('<I',self.fixture['operation_mode']))
            self.uc.mem_write(self.socket+0x4c,struct.pack('<I',self.fixture['interval']))
            self.uc.mem_write(self.socket+0x50,struct.pack('<I',self.fixture['state']))
            self.uc.mem_write(self.socket+0x5c,bytes([self.fixture['write_interest']]))
            table=int.from_bytes(self.uc.mem_read(self.job,8),'little')
            run,done=struct.unpack('<QQ',bytes(self.uc.mem_read(table+0x10,16)))
            if (run,done)!=(RUN,DONE):raise ValueError('Socket job table changed')
            self.worker=True
            self.uc.mem_write(self.stack,struct.pack('<Q',self.stop))
            self.uc.reg_write(x.UC_X86_REG_RSP,self.stack);self.uc.reg_write(x.UC_X86_REG_RCX,self.job)
            try:self.uc.emu_start(run,self.stop,count=4096)
            except Exception as exc:raise ValueError('Worker failed '+self.fixture['name']+' at '+hex(self.uc.reg_read(x.UC_X86_REG_RIP))) from exc
            if self.uc.reg_read(x.UC_X86_REG_RIP) not in (self.stop,0x1445e82d2):raise ValueError('Readiness iteration budget')
            self.worker=False
            for code in self.completions:
                self.events.append(dict(action='fixture_completion_drain',code=code))
                self.run(done,self.job,code)
        return dict(fixture=self.fixture,mode_result=mode_result,
            mode_byte_after=int.from_bytes(self.uc.mem_read(self.socket+0x3c,1),'little'),
            state_after=int.from_bytes(self.uc.mem_read(self.socket+0x50,4),'little'),
            write_interest_after=int.from_bytes(self.uc.mem_read(self.socket+0x5c,1),'little'),
            completion_codes=self.completions,events=self.events)


def build():
    path=native.ROOT/'code-clues/winsock-error-mapping-replay.json'
    prior=json.loads(path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Readiness source changed')
    image=native.Image(raw)
    addresses=(MODE,RUN,0x1445f0c60,0x1444dff20)
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in addresses})
    cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
    def code_span(address,size):
        off=image.offset(address-image.pe.base);data=raw[off:off+size];rows=[]
        for i in cs.disasm(data,address):
            refs=[i.address+i.size+op.mem.disp for op in i.operands if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
            rows.append(dict(address=i.address,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=refs))
        if sum(len(bytes.fromhex(r['bytes'])) for r in rows)!=size:raise ValueError('Readiness leaf decode changed')
        return dict(address=address,file_offset=off,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest(),instructions=rows)
    completion=code_span(DONE,0x73)
    # Confirm actual handle getter bounded leaf before fixture-dependent job execution.
    handle=code_span(0x14184dba0,4)
    if handle['instructions'][-1]['mnemonic']!='ret':raise ValueError('Socket handle getter changed')
    off=image.offset(TABLE-image.pe.base);table=raw[off:off+32]
    if struct.unpack_from('<QQ',table,0x10)!=(RUN,DONE):raise ValueError('Socket readiness vtable changed')
    spec=importlib.util.spec_from_file_location('readiness_imports',HERE/'build-headless-send-drain.py')
    imp=importlib.util.module_from_spec(spec);spec.loader.exec_module(imp)
    dll=Path(prior['winsock_dll']['path']);dllraw=dll.read_bytes();di=native.Image(dllraw)
    imports=[]
    for iat,expected in ((0x148945a00,'select'),(0x148945a58,'ioctlsocket')):
        info=imp.ordinal_import(raw,image,iat);exp=connect.export_name(dllraw,di,info)
        if exp['name']!=expected:raise ValueError('Readiness export name changed')
        imports.append(dict(import_info=info,export=exp))
    fd_info=imp.ordinal_import(raw,image,0x148945b10)
    fd=dict(import_info=fd_info,export=connect.export_name(dllraw,di,fd_info))
    if fd['export']['name']!='__WSAFDIsSet':raise ValueError('FD set import changed')
    fd_thunk=code_span(0x14878bc70,6)
    if fd_thunk['instructions'][0]['rip_references']!=[fd_info['iat_address']]:raise ValueError('FD set jump binding changed')
    engine_table=bytes.fromhex(prior['engine_vtable']['bytes'])
    if struct.unpack_from('<Q',engine_table,0x30)[0]!=0x1445f0c60:raise ValueError('Ioctl engine target binding changed')
    base=dict(handle=42,ioctl_return=0,enqueue_ok=True,operation_mode=0,interval=2,state=2,write_interest=False,
              select_return=1,read_ready=False,write_ready=True,exception_ready=False,option_ok=True,option_error=0)
    fixtures=[dict(base,name='connect-ready'),dict(base,name='no-ready',write_ready=False,select_return=0),
        dict(base,name='option-fail',option_ok=False),dict(base,name='option-error',option_error=10061),
        dict(base,name='exception',write_ready=False,exception_ready=True),dict(base,name='select-error',select_return=-1),
        dict(base,name='stopped',state=8),dict(base,name='read-event',state=6,write_ready=False,read_ready=True),
        dict(base,name='write-event',state=6,write_interest=True),dict(base,name='read-write',state=6,write_interest=True,read_ready=True),
        dict(base,name='operation-one',operation_mode=1,read_ready=True),dict(base,name='ioctl-fail',ioctl_return=-1),
        dict(base,name='enqueue-fail',enqueue_ok=False),dict(base,name='zero-handle',handle=0)]
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fragments=fragments,completion_leaf=completion,handle_leaf=handle,imports=imports,fd_import=fd,fd_thunk=fd_thunk,
        engine_vtable=prior['engine_vtable'],
        job_vtable=dict(address=TABLE,file_offset=off,bytes=table.hex(),sha256=hashlib.sha256(table).hexdigest()),
        winsock_dll=dict(path=str(dll),sha256=hashlib.sha256(dllraw).hexdigest()),
        cases=[Replay(raw,image,fragments,completion,handle,f).capture() for f in fixtures],native_execution=True,network_ready=False,
        limitations=[
            'Actual socket mode helper, engine ioctl body, job run iteration and completion leaf execute.',
            'Syscalls ioctl/select/FD set and engine socket option are fixtures; no actual socket readiness measured.',
            'State/mode/interval inputs after enqueue explicit fixtures; no active client state or valid global sequencing claim.',
            'Worker stops before second select; completion manually drained, real scheduler/thread/lifetime not executed.',
            'Notification dispatch targets captured; recipients, retry and packet Login not executed.',
            'Engine option selector1 is raw source evidence; actual SO_ERROR translation still unverified.',
            'No game launch/profile/process memory/credentials/network/Android parity used.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/socket-readiness-job-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
