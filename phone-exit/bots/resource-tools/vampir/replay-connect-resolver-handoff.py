"""Native lower-connect setup and lexical resolver dispatch; no actual DNS or sockets."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('resolver_connect',HERE/'replay-game-connect-target.py')
connect=importlib.util.module_from_spec(spec);spec.loader.exec_module(connect)
native,x=connect.native,connect.x
LOWER,RESOLVE,HEX=0x1445ea1b0,0x1445e6d70,0x1445e7b10


class Replay(connect.Replay):
    def __init__(self,raw,image,fragments,spans,hex_leaf,fixture):
        super().__init__(raw,image,fragments,spans,fixture)
        rows=[r for f in fragments if f['root_begin_rva']+image.pe.base in (LOWER,RESOLVE) for r in f['instructions']]
        rows+=hex_leaf['instructions']
        self.allowed.update(r['address'] for r in rows)
        self.resolver_hooks={0x1445e5a50,0x1445d8a50,0x1445ddd10,0x1414a94f0,0x1445ef040,
            0x148796040,0x1445de9f0,0x1445e38a0,0x1445d90b0,0x1445da5e0,0x1445db8a0,0x1445dc380}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in self.resolver_hooks)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.weak_refs=[]
        for offset in (0x40,0x58):
            obj=self.allocate(16);ref=self.allocate(32)
            self.uc.mem_write(ref+8,struct.pack('<II',4,5 if fixture['already_listed'] else 4));self.weak_refs.append(ref)
            self.uc.mem_write(self.transport+offset,struct.pack('<QQ',obj,ref))
        for offset in (0xd0,0x118):
            slots=self.allocate(32)
            self.uc.mem_write(self.transport+offset+8,struct.pack('<QQQQ',slots,4,0,1 if fixture['already_listed'] else 0))
            if fixture['already_listed']:
                cell=self.allocate(16)
                source=self.transport+(0x40 if offset==0xd0 else 0x58)
                self.uc.mem_write(cell,bytes(self.uc.mem_read(source,16)))
                self.uc.mem_write(slots,struct.pack('<Q',cell))
        self.resolver_context=self.transport+0xc8
        self.scheduler=self.allocate(32)
        self.resolver_job=None

    def std_write(self,desc,data):
        if not 0<=len(data)<=255:raise ValueError('Resolver std string bound')
        if len(data)<=15:
            self.uc.mem_write(desc,data+b'\0'*(16-len(data)))
            self.uc.mem_write(desc+16,struct.pack('<QQ',len(data),15))
        else:
            ptr=self.allocate(len(data)+1);self.uc.mem_write(ptr,data+b'\0')
            self.uc.mem_write(desc,struct.pack('<QQQQ',ptr,0,len(data),len(data)))

    def std_read(self,desc):
        n,cap=struct.unpack('<QQ',bytes(self.uc.mem_read(desc+16,16)))
        if not 0<=n<=cap<=255:raise ValueError('Resolver std descriptor bound')
        ptr=int.from_bytes(self.uc.mem_read(desc,8),'little') if cap>15 else desc
        return bytes(self.uc.mem_read(ptr,n)).decode('ascii')

    def hook(self,uc,address,size,user):
        if address in (0x1445ea2b3,0x1445ea38e):
            self.events.append(dict(action='native_registration_insert',queue=0 if address==0x1445ea2b3 else 1))
        if address==LOWER:
            self.events.append(dict(action='native_lower_connect_entry'))
        if address==0x144aac031:
            self.events.append(dict(action='native_lower_connect_return',al=uc.reg_read(x.UC_X86_REG_RAX)&255))
        if address in self.allowed:return super().hook(uc,address,size,user)
        if address not in getattr(self,'resolver_hooks',()):return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==0x148796040:
            result=uc.reg_read(x.UC_X86_REG_RAX)  # Cookie-check fixture must preserve native return value.
        elif address==0x1445e5a50:
            self.events.append(dict(action='preconnect_reset_capture'))
        elif address==0x1445d8a50:
            # Explicit dedup lookup fixture; iterator result offset selects native insert or skip.
            end=int.from_bytes(uc.mem_read(c+0x10,8),'little')
            uc.mem_write(a,struct.pack('<QQQ',0,0,end-1 if self.fixture['already_listed'] else end))
        elif address==0x1445ddd10:
            if not 0<=c<=255:raise ValueError('Lower host copy bound')
            self.std_write(a,bytes(uc.mem_read(b,c)));result=a
            self.events.append(dict(action='peer_host_copy_fixture',host=self.std_read(a)))
        elif address==0x1414a94f0:uc.mem_write(a,b'\0'*24)
        elif address==0x1445ef040:
            self.events.append(dict(action='numeric_address_parse_capture',host=self.std_read(b)))
        elif address==0x1445de9f0:
            if a!=self.resolver_context or c!=self.resolver_context:raise ValueError('Numeric resolver context changed')
            self.events.append(dict(action='numeric_result_dispatch_capture',callback=b))
        elif address==0x1445e38a0:pass
        elif address==0x1445d90b0:
            uc.mem_write(a,b'\0'*72);self.resolver_job=a
            self.events.append(dict(action='resolver_job_base_constructor_fixture'))
        elif address==0x1445da5e0:result=self.scheduler
        elif address==0x1445db8a0:
            if a!=self.scheduler or b!=self.resolver_job:raise ValueError('Resolver queue arguments changed')
            if int.from_bytes(uc.mem_read(b+0x20,8),'little')!=self.resolver_context:raise ValueError('Resolver job owner changed')
            host=self.std_read(b+0x28)
            result=self.fixture['enqueue_return']
            self.events.append(dict(action='resolver_job_enqueue_capture',host=host,returned=result))
        elif address==0x1445dc380:self.events.append(dict(action='resolver_job_cancel_capture'))
        else:raise ValueError('Unknown resolver fixture')
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        result=super().capture()
        result['peer_host']=self.std_read(self.transport+0x70)
        result['peer_port']=int.from_bytes(self.uc.mem_read(self.transport+0x90,2),'little')
        result['peer_endpoint_field']=int.from_bytes(self.uc.mem_read(self.transport+0x94,4),'little')
        result['peer_mode']=int.from_bytes(self.uc.mem_read(self.transport+0xc0,4),'little')
        result['registration_counts']=[int.from_bytes(self.uc.mem_read(self.transport+o+0x20,8),'little') for o in (0xd0,0x118)]
        result['registration_weak_counts']=[int.from_bytes(self.uc.mem_read(ref+0xc,4),'little') for ref in self.weak_refs]
        return result


def build():
    path=native.ROOT/'code-clues/game-connect-target-replay.json'
    prior=json.loads(path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Resolver source changed')
    image=native.Image(raw)
    fragments=prior['fragments']+native.decode_ranges(image,{image.roots[image.containing(a)] for a in (LOWER,RESOLVE,0x1445e5a50)})
    cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
    off=image.offset(HEX-image.pe.base);content=raw[off:off+0xb1];rows=[]
    for i in cs.disasm(content,HEX):
        refs=[i.address+i.size+op.mem.disp for op in i.operands if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
        rows.append(dict(address=i.address,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=refs))
    if rows[-1]['address']!=0x1445e7bc0 or rows[-1]['mnemonic']!='ret':raise ValueError('Hex leaf boundary changed')
    leaf=dict(address=HEX,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest(),instructions=rows)
    record=dict(id=42,text='host.invalid',word_30=12345,word_32=22222)
    base=dict(last_id=42,invalid_id=0xffffffff,fallback_id=42,busy=False,records=[record],
              override_text='',override_port=23456,connect_disabled=False,connect_result=True,
              already_listed=False,enqueue_return=1)
    profiles=[]
    for host in ('127.0.0.1','999.999.999.999','1..2','.','::1','ABCDEF','host.invalid','localhost','abc-def'):
        profiles.append(dict(base,name=host,records=[dict(record,text=host)]))
    profiles.append(dict(base,name='enqueue-zero',enqueue_return=0))
    profiles.append(dict(base,name='enqueue-two',enqueue_return=2))
    profiles.append(dict(base,name='already-listed',already_listed=True))
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                fragments=fragments,spans=prior['spans'],hex_leaf=leaf,cases=[Replay(raw,image,fragments,prior['spans'],leaf,f).capture() for f in profiles],
                native_execution=True,network_ready=False,limitations=[
                    'Native BeginGame/connect caller/endpoint/lower-connect/lexical resolver selector execute together.',
                    'Reset, dedup lookup and std-string copies remain fixtures; native two ring insertions execute with preallocated capacity.',
                    'Numeric/hex lexical branch parsing/result dispatch are captures, not validation or actual address resolution.',
                    'Hostname job layout stores execute; job base ctor/scheduler/enqueue are fixtures/captures, no real DNS task runs.',
                    'Enqueue boolean and lower-connect return are synthetic, not TCP connection or game readiness proof.',
                    'No growth/duplicate search correctness/concurrent lifetime/actual cancellation/task completion tested.',
                    'No game launch/process memory/profile/credentials or network calls used.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/connect-resolver-handoff-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
