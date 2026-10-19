"""Native resolved-result broadcast/recipient/socket creation with Winsock fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('socket_resolver',HERE/'replay-resolver-job-results.py')
resolver=importlib.util.module_from_spec(spec);spec.loader.exec_module(resolver)
native,x=resolver.native,resolver.x
DISPATCH,RECIPIENT,CREATE=0x1445de9f0,0x1445e8400,0x1445e5cb0
PEER_TABLE,SOCKET_TABLE=0x14961b8a8,0x149503ac0
SOCKET_HOOK,OPTION_HOOK=0x30000120,0x30000130


class Replay(resolver.Replay):
    def __init__(self,raw,image,fragments,spans,hex_leaf,fixture):
        super().__init__(raw,image,fragments,spans,hex_leaf,fixture)
        rows=[r for f in fragments if f['root_begin_rva']+image.pe.base in (DISPATCH,RECIPIENT,CREATE) for r in f['instructions']]
        # Action JMP body is validated and exported in build().
        self.allowed.update(r['address'] for r in rows);self.allowed.update((0x141423088,0x14142308b))
        self.socket_hooks={0x1445e2010,0x1445ddb70,0x1445dae30,0x1445eefa0,0x1445eab70,
            0x1445e5c60,0x1445dc650,0x1445eeb30,SOCKET_HOOK,OPTION_HOOK}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in (*self.socket_hooks,PEER_TABLE,SOCKET_TABLE,0x141423088))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.uc.mem_write(0x1489459d8,struct.pack('<Q',SOCKET_HOOK))
        self.uc.mem_write(self.transport+0x38,struct.pack('<Q',PEER_TABLE))
        self.uc.mem_write(self.transport+0x40,struct.pack('<Q',self.transport+0x38))
        self.uc.mem_write(self.transport+0x110,struct.pack('<Q',SOCKET_TABLE))
        slots=self.allocate(8*8)
        self.uc.mem_write(self.transport+0x98+8,struct.pack('<QQQQ',slots,8,0,0))
        engine=self.allocate(32);vtable=self.allocate(0x50)
        self.uc.mem_write(engine,struct.pack('<Q',vtable))
        self.uc.mem_write(vtable+0x48,struct.pack('<Q',OPTION_HOOK))
        self.uc.mem_write(0x14b4f39d0,struct.pack('<Q',engine))
        self.socket_stage=False

    def hook(self,uc,address,size,user):
        if address==RECIPIENT:self.events.append(dict(action='native_resolved_recipient_entry'))
        if address==CREATE:self.events.append(dict(action='native_socket_create_entry'))
        if address==DISPATCH and getattr(self,'job_stage',False):self.socket_stage=True
        if address in self.allowed:return super().hook(uc,address,size,user)
        if not getattr(self,'socket_stage',False) or address not in self.socket_hooks:return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==0x1445e2010:
            if b not in (self.transport+0xd0,self.transport+8):raise ValueError('Listener snapshot source changed')
            slots,capacity,head,count=struct.unpack('<QQQQ',bytes(uc.mem_read(b+8,32)))
            owner=self.allocate(16)
            uc.mem_write(a,struct.pack('<QQQQQ',owner,slots,capacity,head,count))
            self.events.append(dict(action='listener_snapshot_fixture',count=count))
        elif address in (0x1445ddb70,0x1445dae30):pass
        elif address==0x1445eefa0:
            slots,capacity,head,count=struct.unpack('<QQQQ',bytes(uc.mem_read(a+8,32)))
            if not count:raise ValueError('Recipient popped empty address queue')
            uc.mem_write(a+0x18,struct.pack('<QQ',(head+1)&(capacity-1),count-1))
            self.events.append(dict(action='candidate_pop_fixture'))
        elif address==SOCKET_HOOK:
            result=self.fixture['socket_return'] & 0xffffffffffffffff
            self.events.append(dict(action='winsock_socket_fixture',family=a,type=b,protocol=c,returned=self.fixture['socket_return']))
        elif address==OPTION_HOOK:
            self.events.append(dict(action='socket_option_capture',selector=d))
            result=1
        elif address==0x1445eab70:
            if a!=self.transport+0x110 or b!=0:raise ValueError('Nonblocking arguments changed')
            result=int(self.fixture['nonblocking_ok'])
            self.events.append(dict(action='socket_mode_capture',arg_edx=b,returned=result))
        elif address==0x1445e5c60:
            if a!=self.transport+0x110:raise ValueError('Socket connect receiver changed')
            self.events.append(dict(action='socket_endpoint_connect_capture',host=self.std_read(b+8),
                port=int.from_bytes(uc.mem_read(b+0x28,2),'little'),family_tag=int.from_bytes(uc.mem_read(b+0x2c,4),'little'),
                returned=self.fixture['socket_connect_ok']))
            result=int(self.fixture['socket_connect_ok'])
        elif address==0x1445dc650:self.events.append(dict(action='socket_failure_report_capture'))
        elif address==0x1445eeb30:self.events.append(dict(action='socket_connect_failure_continuation_capture'))
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        result=super().capture();result['events']=self.events
        result['socket_handle_dword']=int.from_bytes(self.uc.mem_read(self.transport+0x148,4),'little')
        result['queued_candidates']=int.from_bytes(self.uc.mem_read(self.transport+0xb8,8),'little')
        return result



def socket_export(info,system_root):
    path=Path(system_root)/'System32'/info['dll'];raw=path.read_bytes();image=native.Image(raw)
    pe=struct.unpack_from('<I',raw,60)[0];rva,size=struct.unpack_from('<II',raw,pe+24+112)
    off=image.offset(rva)
    base,count,names,functions,name_table,ordinals=struct.unpack_from('<IIIIII',raw,off+16)
    index=info['ordinal']-base
    if not 0<=index<count:raise ValueError('Socket ordinal outside export table')
    for n in range(names):
        op=image.offset(ordinals)+n*2
        if struct.unpack_from('<H',raw,op)[0]!=index:continue
        nrva=struct.unpack_from('<I',raw,image.offset(name_table)+n*4)[0]
        np=image.offset(nrva);end=raw.index(b'\0',np);name=raw[np:end].decode('ascii')
        if name!='socket':raise ValueError('Unexpected Winsock export')
        return dict(path=str(path),sha256=hashlib.sha256(raw).hexdigest(),name=name,
                    export_directory_offset=off,export_directory_bytes=raw[off:off+40].hex(),
                    ordinal_index_offset=op,ordinal_index_bytes=raw[op:op+2].hex(),
                    name_offset=np,name_bytes=raw[np:end+1].hex())
    raise ValueError('Socket export name missing')


def build():
    path=native.ROOT/'code-clues/resolver-job-results-replay.json'
    prior=json.loads(path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Socket recipient source changed')
    image=native.Image(raw)
    addresses=(DISPATCH,RECIPIENT,CREATE,0x1445e2af0,0x144aab540,0x1445e5c60,0x1445eab70,0x1445ecbb0)
    fragments=prior['fragments']+native.decode_ranges(image,{image.roots[image.containing(a)] for a in addresses})
    off=image.offset(0x141423088-image.pe.base);action_bytes=raw[off:off+6]
    if action_bytes.hex()!='488b01ff6008':raise ValueError('Resolved virtual action changed')
    action=dict(address=0x141423088,file_offset=off,bytes=action_bytes.hex(),sha256=hashlib.sha256(action_bytes).hexdigest())
    tables=[]
    for address,size in ((PEER_TABLE,24),(SOCKET_TABLE,32)):
        off=image.offset(address-image.pe.base);content=raw[off:off+size]
        tables.append(dict(address=address,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest()))
    if struct.unpack_from('<Q',bytes.fromhex(tables[0]['bytes']),8)[0]!=RECIPIENT:raise ValueError('Peer recipient vtable changed')
    if struct.unpack_from('<Q',bytes.fromhex(tables[1]['bytes']),8)[0]!=CREATE:raise ValueError('Socket create vtable changed')
    spec=importlib.util.spec_from_file_location('socket_imports',HERE/'build-headless-send-drain.py')
    imports=importlib.util.module_from_spec(spec);spec.loader.exec_module(imports)
    socket_import=imports.ordinal_import(raw,image,0x1489459d8)
    export=socket_export(socket_import,imports.os.environ['SystemRoot'])
    record=dict(id=42,text='resolver-test.invalid',word_30=12345,word_32=22222)
    base=dict(last_id=42,invalid_id=0xffffffff,fallback_id=42,busy=False,records=[record],override_text='',
        override_port=23456,connect_disabled=False,connect_result=True,already_listed=False,enqueue_return=1,dns_return=0,
        socket_return=42,nonblocking_ok=True,socket_connect_ok=True)
    v4=dict(family=2,text='192.0.2.1');v6=dict(family=23,text='2001:db8::1')
    profiles=[dict(base,name='v4',dns_rows=[v4]),dict(base,name='v6',dns_rows=[v6]),
        dict(base,name='mixed',dns_rows=[v4,v6]),dict(base,name='socket-fail',dns_rows=[v4],socket_return=-1),
        dict(base,name='mode-fail',dns_rows=[v4],nonblocking_ok=False),
        dict(base,name='connect-fail',dns_rows=[v4],socket_connect_ok=False),
        dict(base,name='dns-fail',dns_rows=[],dns_return=11001)]
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fragments=fragments,spans=prior['spans'],hex_leaf=prior['hex_leaf'],action_leaf=action,tables=tables,
        socket_import=socket_import,socket_export=export,
        cases=[Replay(raw,image,fragments,prior['spans'],prior['hex_leaf'],f).capture() for f in profiles],native_execution=True,network_ready=False,
        limitations=[
            'Native resolved listener dispatch/action/peer recipient/socket creation caller execute in resolver job chain.',
            'Source peer/socket vtables bind targets; peer interface/ref block/snapshot acquisition are fixtures, full startup not executed.',
            'Winsock socket is a fixture; mode/endpoint connect/options and error continuations are captures.',
            'Address queue copy/pop and cleanup are bounded fixtures; listener lifetime/races/growth/retry policy not verified.',
            'getaddrinfo/inet_ntop/scheduler retain prior fixture boundaries; no real DNS/socket/network calls.',
            'Readiness notification, actual connect/pending interpretation and packet Login remain open.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/resolved-socket-setup-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
