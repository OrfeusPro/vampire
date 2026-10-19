"""Native BeginGame target transfer into ConnectToServer; endpoint/connect are captures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('connect_begin',HERE/'replay-begin-game-server-target.py')
begin=importlib.util.module_from_spec(spec);spec.loader.exec_module(begin)
native,x=begin.native,begin.x
CONNECT=0x144aabcc0


class Replay(begin.Replay):
    def __init__(self,raw,image,fragments,spans,fixture):
        super().__init__(raw,image,fragments,spans,fixture)
        self.connect_stage=False
        rows=[r for f in fragments if f['root_begin_rva'] in (CONNECT-image.pe.base,0x45e2a50) for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        self.connect_hooks={0x141435320,0x1443fca20,0x1414313d0,0x1487a2e19,0x141446a50,
            0x141440af0,0x1445d8e60,0x1414311c0,0x1468e4100,0x14142c480,0x1445e2a50,0x1445ea1b0,0x1445d9550,0x148796040}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in self.connect_hooks)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.string(self.transport+0x290,fixture['override_text'])
        self.uc.mem_write(self.transport+0x2a0,struct.pack('<H',fixture['override_port']))
        self.uc.mem_write(0x14b520cb4,bytes([fixture['connect_disabled']]))
        self.endpoint=None

    def hook(self,uc,address,size,user):
        if address==0x1445e2a50 and getattr(self,'connect_stage',False):
            a,b,c=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
            count,capacity=struct.unpack('<QQ',bytes(uc.mem_read(b+16,16)))
            if not 0<count<=255 or capacity<count:raise ValueError('Endpoint std string layout changed')
            ptr=int.from_bytes(uc.mem_read(b,8),'little') if capacity>15 else b
            host=bytes(uc.mem_read(ptr,count)).decode('ascii')
            self.endpoint=a
            self.events.append(dict(action='endpoint_constructor_entry',host=host,port=c))
        if address in self.allowed:return super().hook(uc,address,size,user)
        if not getattr(self,'connect_stage',False) or address not in self.connect_hooks:
            return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==0x141435320:
            rbp=uc.reg_read(x.UC_X86_REG_RBP);uc.mem_write(rbp-0x20,b'\0'*16)  # Logging conversion only.
        elif address in (0x1443fca20,0x14142c480,0x1445d9550,0x148796040):pass
        elif address==0x1414313d0:
            if not 1<=b<=256:raise ValueError('Connect FString allocation bound')
            count=int.from_bytes(uc.mem_read(a+8,4),'little');pointer=self.allocate(b*2)
            uc.mem_write(a,struct.pack('<QII',pointer,count,b))
        elif address==0x1487a2e19:
            if not 0<=c<=512:raise ValueError('Connect memcpy bound')
            uc.mem_write(a,bytes(uc.mem_read(b,c)));result=a
        elif address==0x141446a50:
            if not 0<=c<=255:raise ValueError('Connect conversion bound')
            text=bytes(uc.mem_read(b,c*2)).decode('utf-16le')
            result=len(text.encode('ascii'))  # Explicit supported fixture subset.
        elif address==0x141440af0:
            if not 1<=d<=256:raise ValueError('Connect UTF16 source bound')
            text=bytes(uc.mem_read(c,d*2)).decode('utf-16le')
            data=text.encode('ascii')
            if not text.endswith('\0') or len(data)>b:raise ValueError('Connect conversion capacity')
            uc.mem_write(a,data);result=len(data)-1
        elif address==0x1414311c0:
            if not 1<=c<=512:raise ValueError('Connect conversion allocation bound')
            uc.mem_write(a,struct.pack('<Q',self.allocate(c)))
        elif address==0x1468e4100:
            if not 1<=a<=512:raise ValueError('Connect std string allocation bound')
            result=self.allocate(a)
        elif address==0x1445d8e60:
            uc.mem_write(a,bytes(uc.mem_read(b,32)));result=a  # Bounded std-string copy fixture, no ownership claim.
        elif address==0x1445ea1b0:
            if a!=self.transport or b!=self.endpoint or c!=0:raise ValueError('Connect arguments changed')
            result=int(self.fixture['connect_result'])
            self.events.append(dict(action='socket_connect_capture',arg_r8d=c,returned=result,
                endpoint_port=int.from_bytes(uc.mem_read(b+0x28,2),'little'),
                endpoint_field_2c=int.from_bytes(uc.mem_read(b+0x2c,4),'little')))
        else:raise ValueError('Unknown connect fixture')
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        result=super().capture()
        if result['stop']!='target_setters_completed':raise ValueError('Connect fixture target not selected')
        self.connect_stage=True
        self.uc.mem_write(self.stack,struct.pack('<Q',self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP,self.stack);self.uc.reg_write(x.UC_X86_REG_RCX,self.transport)
        self.uc.emu_start(CONNECT,self.stop,count=8192)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=self.stop:raise ValueError('Connect native budget')
        result['events']=self.events
        result['busy_after_connect']=int.from_bytes(self.uc.mem_read(self.busy+0x38,1),'little')
        return result


def build():
    path=native.ROOT/'code-clues/begin-game-server-target-replay.json'
    prior=json.loads(path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Connect source changed')
    image=native.Image(raw)
    fragments=prior['fragments']+native.decode_ranges(image,{image.roots[image.containing(a)] for a in (CONNECT,0x1445e2a50)})
    literals=[]
    for f in fragments:
        if f['root_begin_rva']!=CONNECT-image.pe.base:continue
        for row in f['instructions']:
            for ref in row['rip_references']:
                if lit:=begin.dispatch.completion.gates.fields.lifecycle.guid.source.config.read_literal(raw,image,ref):literals.append(dict(instruction=row['address'],**lit))
    record=dict(id=42,text='primary.invalid',word_30=12345,word_32=22222)
    base=dict(last_id=42,invalid_id=0xffffffff,fallback_id=42,busy=False,records=[record],
              override_text='',override_port=23456,connect_disabled=False,connect_result=True)
    fixtures=[dict(base,name='primary'),dict(base,name='long-primary',records=[dict(record,text='long-primary-host.invalid')]),
              dict(base,name='override',override_text='override.invalid'),
              dict(base,name='short-override',override_text='x'),dict(base,name='disabled',connect_disabled=True),
              dict(base,name='empty-primary',records=[dict(record,text='')]),
              dict(base,name='empty-primary-override',records=[dict(record,text='')],override_text='override.invalid'),
              dict(base,name='connect-false',connect_result=False)]
    for port in (0,32767,32768,65535):
        fixtures.append(dict(base,name='port-'+str(port),records=[dict(record,word_30=port)]))
    fixtures.append(dict(base,name='override-high-port',override_text='override.invalid',override_port=65535))
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                fragments=fragments,spans=prior['spans'],literals=literals,
                cases=[Replay(raw,image,fragments,prior['spans'],f).capture() for f in fixtures],native_execution=True,network_ready=False,
                limitations=[
                    'Native BeginGame target selection/setters and ConnectToServer caller execute sequentially in same fixture.',
                    'Endpoint constructor executes actual vtable/port/field writes; its std-string copy is a bounded fixture.',
                    'Lower socket connect is a capture; no DNS/socket/network executed.',
                    'ASCII conversion/allocations/copies/log formatting/cleanup are bounded fixtures.',
                    'Alternate endpoint is selected by nonempty FString count; its active source and role are not established.',
                    'Primary word+0x288 is used as game-server port; word+0x28a consumer remains unknown.',
                    'Native signed 16-bit validation accepts zero and rejects high-bit ports; this is evidence, not portable policy.',
                    'Connect result is synthetic; real readiness, busy rollback, TLS/protocol and game Login remain unverified.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/game-connect-target-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
