"""Native readiness completion, socket/peer broadcasts and transport recipient."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('notify_option',HERE/'replay-socket-error-option.py')
option=importlib.util.module_from_spec(spec);spec.loader.exec_module(option)
ready=option.ready
native,x=option.native,option.x
DISPATCH=0x1445de8b0
SOCKET_RECIPIENT=0x1445e8900
TRANSPORT_RECIPIENT=0x144aac520
SOCKET_LISTENER_TABLE=0x14961b8c0
PEER_LISTENER_TABLE=0x14961b8f0
CALLBACK=0x30000360


class Replay(option.Replay):
    def __init__(self,raw,image,fragments,completion,handle,option_body,extra,leaves,fixture):
        super().__init__(raw,image,fragments,completion,handle,option_body,fixture)
        rows=[r for f in extra if f['root_begin_rva']+image.pe.base in (DISPATCH,TRANSPORT_RECIPIENT) for r in f['instructions']]
        rows += [r for f in leaves for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        self.notification_hooks={0x1445e2010,0x1445dae30,0x1445ddb70,0x14142c480,
            0x14142d840,0x141435320,0x1443fca20,0x14147d580,0x141424430,
            0x1445ead40,0x144aa7510,0x1414400e0,0x1445e2a90,0x1445e7680,
            0x1445d9550,CALLBACK}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in (*self.notification_hooks,SOCKET_LISTENER_TABLE,PEER_LISTENER_TABLE))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        # Synthetic peer layout uses offsets bound to the client constructors.
        old=self.socket;self.peer=self.allocate(0x400);self.socket=self.peer+0x110
        self.uc.mem_write(self.socket,bytes(self.uc.mem_read(old,0x70)))
        self.uc.mem_write(self.peer+0x50,struct.pack('<Q',SOCKET_LISTENER_TABLE))
        self.uc.mem_write(self.peer+0x200,struct.pack('<Q',PEER_LISTENER_TABLE))
        self.uc.mem_write(self.peer+0x108,struct.pack('<I',2))
        self.uc.mem_write(self.peer+0x240,struct.pack('<H',1234))
        self.uc.mem_write(self.peer+0x248,struct.pack('<Q',5678))
        self.uc.mem_write(self.peer+0x2a5,bytes([fixture['special_flag']]))
        self.owner=self.allocate(16);owner_table=self.allocate(0x68)
        self.uc.mem_write(self.owner,struct.pack('<Q',owner_table))
        self.uc.mem_write(owner_table+0x60,struct.pack('<Q',CALLBACK))
        self.uc.mem_write(self.peer+0x308,struct.pack('<Q',self.owner if fixture['owner_present'] else 0))
        self.uc.mem_write(self.peer+0x310,struct.pack('<I',fixture['owner_count']))
        self.refs=[];self.queues={}
        for address,listener,kind in ((self.socket+8,self.peer+0x50,'socket'),(self.peer+8,self.peer+0x200,'peer')):
            slots=self.allocate(32);cell=self.allocate(16);ref=self.allocate(32)
            strong=0 if fixture['expired']==kind else 4
            self.uc.mem_write(ref+8,struct.pack('<II',strong,4));self.refs.append(ref)
            self.uc.mem_write(cell,struct.pack('<QQ',0 if fixture['null_listener']==kind else listener,ref))
            self.uc.mem_write(slots,struct.pack('<Q',cell))
            count=0 if fixture['empty']==kind else 1
            self.uc.mem_write(address+8,struct.pack('<QQQQ',slots,4,0,count))
            self.queues[address]=kind

    def hook(self,uc,address,size,user):
        if address==SOCKET_RECIPIENT:
            self.events.append(dict(action='native_socket_ready_recipient'))
        if address==TRANSPORT_RECIPIENT:
            self.events.append(dict(action='native_transport_ready_recipient'))
        if address in self.allowed:return super().hook(uc,address,size,user)
        if address not in self.notification_hooks:return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==0x1445e2010:
            kind=self.queues[b]
            slots,capacity,head,count=struct.unpack('<QQQQ',bytes(uc.mem_read(b+8,32)))
            owner=self.allocate(16);uc.mem_write(a,struct.pack('<QQQQQ',owner,slots,capacity,head,count))
            self.events.append(dict(action='listener_snapshot_fixture',queue=kind,count=count))
        elif address==0x1445dae30:
            self.events.append(dict(action='listener_prune_capture',queue=self.queues[a+8]))
        elif address in (0x1445ddb70,0x14142c480,0x14147d580,0x1445d9550):pass
        elif address==0x14142d840:
            uc.mem_write(a,b'\0'*16)
        elif address==0x141435320:
            # Diagnostic formatter only; its result is never used as protocol data.
            uc.mem_write(a,b'\0'*0x90)
        elif address in (0x1443fca20,0x141424430):pass
        elif address==0x1445ead40:
            if a!=self.socket:raise ValueError('Ready transport socket getter changed')
            self.events.append(dict(action='socket_configuration_capture',arg_edx=b,arg_r8d=c,arg_r9b=d & 255))
        elif address==0x144aa7510:
            result=self.allocate(0x40)
        elif address==0x1414400e0:
            self.events.append(dict(action='special_flag_helper_capture'))
        elif address==0x1445e2a90:
            uc.mem_write(a,b'\0'*0x40)
        elif address==0x1445e7680:
            if a!=self.socket:raise ValueError('Ready endpoint getter socket changed')
            self.events.append(dict(action='connected_endpoint_getter_fixture',returned=False))
        elif address==CALLBACK:
            if a!=self.owner:raise ValueError('Ready owner callback changed')
            self.events.append(dict(action='owner_virtual_60_capture',string_descriptor=bytes(uc.mem_read(b,16)).hex()))
        else:raise ValueError('Unknown readiness notification fixture')
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=int.from_bytes(uc.mem_read(rsp,8),'little')
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        result=super().capture()
        result.update(peer_state_after=int.from_bytes(self.uc.mem_read(self.peer+0x108,4),'little'),
            transport_word_after=int.from_bytes(self.uc.mem_read(self.peer+0x240,2),'little'),
            transport_qword_after=int.from_bytes(self.uc.mem_read(self.peer+0x248,8),'little'),
            special_bytes_after=bytes(self.uc.mem_read(self.peer+0x2a5,2)).hex(),
            listener_strong_counts=[int.from_bytes(self.uc.mem_read(p+8,4),'little') for p in self.refs])
        return result


def build():
    prior_path=native.ROOT/'code-clues/socket-error-option-replay.json'
    prior=json.loads(prior_path.read_text('utf-8'))
    ready_path=native.ROOT/'code-clues/socket-readiness-job-replay.json'
    upstream=json.loads(ready_path.read_text('utf-8'))
    raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Notification source changed')
    image=native.Image(raw)
    extra=native.decode_ranges(image,{image.roots[image.containing(a)] for a in (DISPATCH,TRANSPORT_RECIPIENT,0x1445e2af0,0x144aab540,0x1445ea1b0,0x1445d91c0)})
    instructions={r['address']:r for f in extra for r in f['instructions']}
    bindings=[]
    for address,mnemonic,operands in (
        (0x1445e2b50,'lea','rcx, [rsi + 0x50]'),
        (0x1445e2b58,'call','0x1445d91c0'),
        (0x1445d91cd,'mov','qword ptr [rcx + 8], rcx'),
        (0x144aab5bb,'mov','qword ptr [rsi + 0x50], rax'),
        (0x1445ea2c1,'lea','rbx, [rdi + 0x118]'),
        (0x1445ea324,'mov','r15, qword ptr [rdi + 0x58]'),
        (0x1445ea38e,'mov','qword ptr [rcx], r15'),
        (0x144aab568,'lea','rcx, [rsi + 0x200]'),
        (0x144aab56f,'call','0x1445d91c0'),
        (0x144aab5c6,'mov','qword ptr [rsi + 0x200], rax'),
        (0x144aab608,'lea','r9, [rsi + 0x208]'),
        (0x144aab6f2,'mov','r14, qword ptr [rsi + 0x208]'),
        (0x144aab756,'mov','qword ptr [rcx], r14')):
        row=instructions[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Subscriber source binding changed')
        bindings.append(row)
    for address,target in ((0x144aab5b4,SOCKET_LISTENER_TABLE),(0x144aab5bf,PEER_LISTENER_TABLE)):
        row=instructions[address]
        if row['mnemonic']!='lea' or row['rip_references']!=[target]:raise ValueError('Subscriber table constructor changed')
        bindings.append(row)
    cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
    leaves=[]
    for address,size in ((0x14370ae90,6),(0x1445c018c,6),(SOCKET_RECIPIENT,0x1d),(0x143231f80,8)):
        off=image.offset(address-image.pe.base);content=raw[off:off+size];rows=[]
        for i in cs.disasm(content,address):
            refs=[i.address+i.size+op.mem.disp for op in i.operands if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
            rows.append(dict(address=i.address,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=refs))
        if sum(len(bytes.fromhex(r['bytes'])) for r in rows)!=size:raise ValueError('Notification leaf decode changed')
        leaves.append(dict(address=address,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest(),instructions=rows))
    if leaves[0]['bytes']!='488b01ff6010' or leaves[1]['bytes']!='488b01ff6018':raise ValueError('Notification virtual actions changed')
    tables=[]
    for address,slot,target in ((SOCKET_LISTENER_TABLE,0x10,SOCKET_RECIPIENT),(PEER_LISTENER_TABLE,0x18,TRANSPORT_RECIPIENT)):
        off=image.offset(address-image.pe.base);content=raw[off:off+slot+8]
        if struct.unpack_from('<Q',content,slot)[0]!=target:raise ValueError('Notification recipient vtable changed')
        tables.append(dict(address=address,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest()))
    diagnostics=[]
    for address,encoding,expected in ((0x14961bcb0,'ascii',None),
        (0x14961bcf0,'utf-16le','NnPeerImpl::OnTcpPeerConnected()')):
        off=image.offset(address-image.pe.base);unit=2 if encoding=='utf-16le' else 1
        end=off
        while end-off<256 and raw[end:end+unit]!=b'\0'*unit:end+=unit
        content=raw[off:end+unit];text=content[:-unit].decode(encoding)
        if expected and text!=expected:raise ValueError('Transport diagnostic name changed')
        refs=[r for r in instructions.values() if address in r['rip_references']]
        if len(refs)!=1:raise ValueError('Transport diagnostic reference changed')
        diagnostics.append(dict(address=address,file_offset=off,bytes=content.hex(),
            sha256=hashlib.sha256(content).hexdigest(),encoding=encoding,text=text,reference=refs[0]))
    base=dict(upstream['cases'][0]['fixture'],syscall_return=0,owner_present=True,owner_count=1,
        empty='',expired='',null_listener='',special_flag=False)
    fixtures=[dict(base,name='ready-owner'),dict(base,name='no-owner-count',owner_count=0),
        dict(base,name='null-owner',owner_present=False),dict(base,name='empty-socket',empty='socket'),
        dict(base,name='empty-peer',empty='peer'),dict(base,name='expired-socket',expired='socket'),
        dict(base,name='expired-peer',expired='peer'),dict(base,name='null-socket-listener',null_listener='socket'),
        dict(base,name='null-peer-listener',null_listener='peer'),dict(base,name='special-flag',special_flag=True)]
    args=(raw,image,upstream['fragments'],upstream['completion_leaf'],upstream['handle_leaf'],prior['option_body'],extra,leaves)
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
        readiness_upstream_sha256=hashlib.sha256(ready_path.read_bytes()).hexdigest(),
        fragments=extra,leaves=leaves,tables=tables,subscriber_source_bindings=bindings,diagnostics=diagnostics,
        cases=[Replay(*args,f).capture() for f in fixtures],native_execution=True,network_ready=False,
        limitations=['Actual completion, two broadcasts, virtual action leaves and transport recipient execute.',
            'Peer/subscriber objects and queues are fixtures bound to constructor/registration offsets; constructors not executed.',
            'Diagnostic formatters/configuration/connected endpoint getter and owner virtual60 remain captures/fixtures.',
            'Endpoint getter returns false, so only empty endpoint string owner callback covered.',
            'Snapshot allocation/prune/free and scheduler remain captures; no listener races/lifetime proof.',
            'Socket syscalls are fixtures, one worker iteration and manual completion drain retained.',
            'No actual Login, game launch/profile/process memory/credentials/network or Android execution.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/socket-ready-notification-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
