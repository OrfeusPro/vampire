"""Execute the source socket option translation inside the readiness job."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('option_readiness',HERE/'replay-socket-readiness-job.py')
ready=importlib.util.module_from_spec(spec);spec.loader.exec_module(ready)
native,x=ready.native,ready.x
OPTION=0x1445f0b10
SYSCALL=0x30000350


class Replay(ready.Replay):
    def __init__(self,raw,image,fragments,completion,handle,option,fixture):
        super().__init__(raw,image,fragments,completion,handle,fixture)
        self.allowed.update(r['address'] for r in option['instructions'])
        # Includes the adjacent 18-entry source switch table, which is data.
        page=OPTION & ~4095
        if not any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):
            self.uc.mem_map(page,4096)
            off=image.offset(page-image.pe.base);self.uc.mem_write(page,raw[off:off+4096])
        self.uc.mem_write(self.vtable+0x60,struct.pack('<Q',OPTION))
        self.uc.mem_write(0x148945b30,struct.pack('<Q',SYSCALL))

    def hook(self,uc,address,size,user):
        if address!=SYSCALL:
            return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        rsp=uc.reg_read(x.UC_X86_REG_RSP)
        sizeptr=int.from_bytes(uc.mem_read(rsp+0x28,8),'little')
        size_before=int.from_bytes(uc.mem_read(sizeptr,4),'little')
        if a!=self.fixture['handle'] or size_before!=4:
            raise ValueError('Socket option handle/size changed')
        uc.mem_write(d,struct.pack('<I',self.fixture['option_error']))
        uc.mem_write(sizeptr,struct.pack('<I',self.fixture.get('output_size',4)))
        result=self.fixture['syscall_return']
        self.events.append(dict(action='getsockopt_fixture',handle=a,level=b,option=c,
            size_before=size_before,size_after=self.fixture.get('output_size',4),
            output=self.fixture['option_error'],returned=result))
        uc.reg_write(x.UC_X86_REG_RAX,result & 0xffffffffffffffff)
        target=int.from_bytes(uc.mem_read(rsp,8),'little')
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)


def build():
    prior_path=native.ROOT/'code-clues/socket-readiness-job-replay.json'
    prior=json.loads(prior_path.read_text('utf-8'))
    raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Option source changed')
    image=native.Image(raw)
    source_table=bytes.fromhex(prior['engine_vtable']['bytes'])
    if struct.unpack_from('<Q',source_table,0x60)[0]!=OPTION:raise ValueError('Option source vtable changed')
    offset=image.offset(OPTION-image.pe.base)
    code=raw[offset:offset+0xfa]  # Through RET; padding/table are not code.
    cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
    rows=[]
    for i in cs.disasm(code,OPTION):
        refs=[i.address+i.size+op.mem.disp for op in i.operands if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
        rows.append(dict(address=i.address,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=refs))
    if sum(len(bytes.fromhex(r['bytes'])) for r in rows)!=len(code) or rows[-1]['mnemonic']!='ret':
        raise ValueError('Option bounded decode changed')
    calls=[r for r in rows if r['mnemonic']=='call']
    if len(calls)!=1 or calls[0]['rip_references']!=[0x148945b30]:raise ValueError('Option import binding changed')
    option=dict(address=OPTION,file_offset=offset,bytes=code.hex(),sha256=hashlib.sha256(code).hexdigest(),instructions=rows)
    switch_address=0x1445f0c0c;off=image.offset(switch_address-image.pe.base);switch=raw[off:off+18*4]
    spec=importlib.util.spec_from_file_location('option_imports',HERE/'build-headless-send-drain.py')
    imp=importlib.util.module_from_spec(spec);spec.loader.exec_module(imp)
    info=imp.ordinal_import(raw,image,0x148945b30)
    dll=Path(prior['winsock_dll']['path']);dllraw=dll.read_bytes()
    export=ready.connect.export_name(dllraw,native.Image(dllraw),info)
    if export['name']!='getsockopt':raise ValueError('Option export changed')
    base=dict(prior['cases'][0]['fixture'],syscall_return=0)
    fixtures=[dict(base,name='ready-zero'),dict(base,name='pending-error',option_error=10035),
        dict(base,name='refused-error',option_error=10061),dict(base,name='syscall-fail',syscall_return=-1),
        dict(base,name='positive-return',syscall_return=1),dict(base,name='changed-output-size',output_size=0),
        dict(base,name='no-write',write_ready=False,select_return=0),dict(base,name='exception',write_ready=False,exception_ready=True)]
    args=(raw,image,prior['fragments'],prior['completion_leaf'],prior['handle_leaf'],option)
    cases=[Replay(*args,f).capture() for f in fixtures]
    # Exercise every raw option selector and boundary. Direct native calls use
    # the same source vtable target; no socket/options are queried on this host.
    mappings=[]
    for level in (0,1,2,3,4):
        for selector in range(19):
            r=Replay(*args,base);out=r.allocate(4);length=r.allocate(4)
            r.uc.mem_write(length,struct.pack('<I',4))
            r.uc.mem_write(r.stack,struct.pack('<Q',r.stop))
            r.uc.mem_write(r.stack+0x28,struct.pack('<Q',out))
            r.uc.mem_write(r.stack+0x30,struct.pack('<Q',length))
            for reg,value in ((x.UC_X86_REG_RSP,r.stack),(x.UC_X86_REG_RCX,r.engine),
                (x.UC_X86_REG_RDX,42),(x.UC_X86_REG_R8,level),(x.UC_X86_REG_R9,selector)):
                r.uc.reg_write(reg,value)
            r.uc.emu_start(OPTION,r.stop,count=4096)
            if r.uc.reg_read(x.UC_X86_REG_RIP)!=r.stop:raise ValueError('Option direct budget')
            mappings.append(dict(level_selector=level,option_selector=selector,
                returned=r.uc.reg_read(x.UC_X86_REG_RAX)&255,events=r.events))
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
        option_body=option,engine_vtable=prior['engine_vtable'],
        switch_table=dict(address=switch_address,file_offset=off,bytes=switch.hex(),sha256=hashlib.sha256(switch).hexdigest()),
        import_info=info,export=export,winsock_dll=dict(path=str(dll),sha256=hashlib.sha256(dllraw).hexdigest()),
        cases=cases,mappings=mappings,native_execution=True,network_ready=False,
        limitations=['Actual engine option translation executes inside the bounded readiness job.',
            'getsockopt/select/ioctl/FDIsSet are fixtures; no real socket, OS error or session measured.',
            'Raw level/option constants verified; symbolic OS header names not asserted.',
            'One worker iteration and manual completion drain; scheduler/recipients/lifetime remain captures.',
            'No game launch, profile, process memory, credentials, network or Android execution.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/socket-error-option-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']),mappings=len(report['mappings']))))
