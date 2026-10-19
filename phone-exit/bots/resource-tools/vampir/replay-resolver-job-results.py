"""Native resolver job run/completion over explicit Winsock result fixtures, no DNS."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('job_handoff',HERE/'replay-connect-resolver-handoff.py')
handoff=importlib.util.module_from_spec(spec);spec.loader.exec_module(handoff)
native,x=handoff.native,handoff.x
RUN,DONE,TABLE=0x1445e7e00,0x1445e7cf0,0x149503a80
DNS_HOOK=0x30000100


class Replay(handoff.Replay):
    def __init__(self,raw,image,fragments,spans,hex_leaf,fixture):
        super().__init__(raw,image,fragments,spans,hex_leaf,fixture)
        rows=[r for f in fragments if f['root_begin_rva']+image.pe.base in (RUN,DONE) for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        self.job_hooks={DNS_HOOK,0x14878bc7c,0x1421e1620,0x1445dad30,0x1445de8b0,0x1445e3110}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in self.job_hooks)
        pages.add(TABLE & ~4095)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.uc.mem_write(0x148945ae0,struct.pack('<Q',DNS_HOOK))
        self.job_stage=False;self.pending_completion=None;self.result_payload=None
        self.addr_rows={}
        self.vector=None;self.vector_count=0

    def ctext(self,pointer):
        data=bytearray()
        for n in range(256):
            value=bytes(self.uc.mem_read(pointer+n,1))
            if value==b'\0':return data.decode('ascii')
            data.extend(value)
        raise ValueError('DNS fixture string bound')

    def results(self,payload):
        start,end=struct.unpack('<QQ',bytes(self.uc.mem_read(payload+0x38,16)))
        if end<start or (end-start)%32 or end-start>8*32:raise ValueError('Resolver result vector bound')
        return [self.std_read(start+n*32) for n in range((end-start)//32)]

    def hook(self,uc,address,size,user):
        if address in self.allowed:return super().hook(uc,address,size,user)
        if not getattr(self,'job_stage',False):return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==DNS_HOOK:
            host=self.ctext(a);flags,family,socktype,protocol=struct.unpack('<IIII',bytes(uc.mem_read(c,16)))
            self.events.append(dict(action='getaddrinfo_fixture',host=host,service_null=b==0,
                                    hints=[flags,family,socktype,protocol],returned=self.fixture['dns_return']))
            nodes=[self.allocate(48) for _ in self.fixture['dns_rows']]
            for n,row in enumerate(self.fixture['dns_rows']):
                addr=self.allocate(32)
                uc.mem_write(nodes[n]+4,struct.pack('<I',row['family']))
                uc.mem_write(nodes[n]+0x20,struct.pack('<QQ',addr,nodes[n+1] if n+1<len(nodes) else 0))
                self.addr_rows[addr+(4 if row['family']==2 else 8)]=row
            uc.mem_write(d,struct.pack('<Q',nodes[0] if nodes and not self.fixture['dns_return'] else 0))
            result=self.fixture['dns_return']
        elif address==0x14878bc7c:
            row=self.addr_rows[b]
            if a!=row['family']:raise ValueError('DNS family pointer offset changed')
            data=row['text'].encode('ascii')+b'\0'
            if len(data)>d:raise ValueError('inet_ntop fixture capacity')
            uc.mem_write(c,data);result=c
            self.events.append(dict(action='inet_ntop_fixture',family=a,text=row['text']))
        elif address==0x1421e1620:
            if not 0<c<=255:raise ValueError('DNS std string bound')
            self.std_write(a,bytes(uc.mem_read(b,c)));result=a
        elif address==0x1445ef040:
            if self.vector is None:self.vector=self.allocate(8*32)
            if self.vector_count>=8:raise ValueError('DNS vector capacity fixture')
            value=self.std_read(b);self.std_write(self.vector+self.vector_count*32,value.encode('ascii'))
            self.vector_count+=1
            uc.mem_write(a,struct.pack('<QQQ',self.vector,self.vector+self.vector_count*32,self.vector+8*32))
            self.events.append(dict(action='resolved_vector_append_fixture',text=value))
        elif address==0x1445dad30:
            if a!=self.resolver_job or b!=0 or d!=0:raise ValueError('Resolver completion arguments changed')
            self.result_payload=c;self.pending_completion=(a,b,c,d)
            self.events.append(dict(action='job_completion_schedule_capture',payload_present=bool(c)))
        elif address==0x1445de9f0:
            if a!=self.resolver_context or c!=self.resolver_context or d!=self.result_payload:
                raise ValueError('Resolved-result callback arguments changed')
            self.events.append(dict(action='resolved_result_dispatch_capture',callback=b,addresses=self.results(d)))
        elif address==0x1445de8b0:
            if a!=self.resolver_context or c!=self.resolver_context:raise ValueError('Failure callback context changed')
            self.events.append(dict(action='resolver_failure_dispatch_capture',callback=b))
        elif address==0x1445e3110:
            self.events.append(dict(action='resolver_payload_destroy_capture'))
        elif address in self.job_hooks:raise ValueError('Unhandled DNS fixture')
        else:return super().hook(uc,address,size,user)
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def call_job(self,target,a,b=0,c=0,d=0):
        self.uc.mem_write(self.stack,struct.pack('<Q',self.stop))
        for reg,value in ((x.UC_X86_REG_RSP,self.stack),(x.UC_X86_REG_RCX,a),(x.UC_X86_REG_RDX,b),
                          (x.UC_X86_REG_R8,c),(x.UC_X86_REG_R9,d)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(target,self.stop,count=8192)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=self.stop:raise ValueError('Resolver job native budget')

    def capture(self):
        result=super().capture();self.job_stage=True
        if not self.resolver_job:raise ValueError('No queued DNS fixture job')
        vtable=int.from_bytes(self.uc.mem_read(self.resolver_job,8),'little')
        run,done=struct.unpack('<QQ',bytes(self.uc.mem_read(vtable+0x10,16)))
        if (run,done)!=(RUN,DONE):raise ValueError('Resolver job virtual targets changed')
        self.events.append(dict(action='fixture_job_drain',run=run))
        self.call_job(run,self.resolver_job)
        if self.pending_completion is None:raise ValueError('No completion scheduled')
        snapshot=self.results(self.result_payload) if self.result_payload else None
        self.events.append(dict(action='fixture_completion_drain',done=done))
        self.call_job(done,*self.pending_completion)
        result['events']=self.events
        result['result_addresses']=snapshot
        return result


def build():
    path=native.ROOT/'code-clues/connect-resolver-handoff-replay.json'
    prior=json.loads(path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Resolver job source changed')
    image=native.Image(raw)
    fragments=prior['fragments']+native.decode_ranges(image,{image.roots[image.containing(a)] for a in (RUN,DONE)})
    spec=importlib.util.spec_from_file_location('resolver_imports',HERE/'build-object-zero-init-code.py')
    imports=importlib.util.module_from_spec(spec);spec.loader.exec_module(imports)
    dns_import=imports.import_at(raw,image,0x148945ae0)
    ntop_import=imports.import_at(raw,image,0x148945b18)
    if dns_import['name']!='getaddrinfo' or ntop_import['name'].lower()!='inet_ntop':raise ValueError('Resolver imports changed')
    ntop_address=0x14878bc7c;ntop_offset=image.offset(ntop_address-image.pe.base)
    ntop_bytes=raw[ntop_offset:ntop_offset+6]
    if ntop_bytes[:2]!=b'\xff\x25' or ntop_address+6+struct.unpack('<i',ntop_bytes[2:])[0]!=ntop_import['iat_address']:
        raise ValueError('inet_ntop jump/import binding changed')
    ntop_thunk=dict(address=ntop_address,file_offset=ntop_offset,bytes=ntop_bytes.hex(),
                    sha256=hashlib.sha256(ntop_bytes).hexdigest(),iat_address=ntop_import['iat_address'])
    dns_rows=[r for f in fragments for r in f['instructions'] if r['address']==0x1445e7e62]
    if len(dns_rows)!=1 or dns_rows[0]['rip_references']!=[dns_import['iat_address']]:
        raise ValueError('getaddrinfo call/import binding changed')
    offset=image.offset(TABLE-image.pe.base);table=raw[offset:offset+32]
    if struct.unpack_from('<QQ',table,0x10)!=(RUN,DONE):raise ValueError('Resolver table changed')
    record=dict(id=42,text='resolver-test.invalid',word_30=12345,word_32=22222)
    base=dict(last_id=42,invalid_id=0xffffffff,fallback_id=42,busy=False,records=[record],override_text='',
              override_port=23456,connect_disabled=False,connect_result=True,already_listed=False,enqueue_return=1,dns_return=0)
    v4=dict(family=2,text='192.0.2.1');v6=dict(family=23,text='2001:db8::1')
    profiles=[dict(base,name='v4',dns_rows=[v4]),dict(base,name='v6',dns_rows=[v6]),
              dict(base,name='v4-v6',dns_rows=[v4,v6]),dict(base,name='v6-v4',dns_rows=[v6,v4]),
              dict(base,name='v4-v4-v6',dns_rows=[v4,dict(v4,text='192.0.2.2'),v6]),
              dict(base,name='unsupported-family',dns_rows=[dict(family=99,text='unused')]),
              dict(base,name='empty-results',dns_rows=[]),dict(base,name='dns-error',dns_return=11001,dns_rows=[])]
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                fragments=fragments,spans=prior['spans'],hex_leaf=prior['hex_leaf'],
                resolver_vtable=dict(address=TABLE,file_offset=offset,bytes=table.hex(),sha256=hashlib.sha256(table).hexdigest()),
                imports=[dns_import,ntop_import],inet_ntop_thunk=ntop_thunk,cases=[Replay(raw,image,fragments,prior['spans'],prior['hex_leaf'],f).capture() for f in profiles],
                native_execution=True,network_ready=False,limitations=[
                    'Native resolver job run/completion execute after source-bound virtual targets are manually drained.',
                    'Winsock getaddrinfo/inet_ntop are explicit fixtures; no actual DNS, sockaddr conversion or sockets executed.',
                    'String/vector append and cleanup are bounded fixtures; native family traversal/order swap and callback gates execute.',
                    'Scheduler/completion handoff are captures with explicit manual drains; no real threads/lifetime/races.',
                    'Resolved/failure callback dispatch is a capture; downstream recipient and socket readiness not executed.',
                    'Address order evidence is Windows-specific; no portable policy or Android parity claimed.',
                    'No game launch/process memory/profile/credentials/network used.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/resolver-job-results-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
