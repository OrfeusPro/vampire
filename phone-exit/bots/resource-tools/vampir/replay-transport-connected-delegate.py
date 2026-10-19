"""Execute native connection-delegate binding and bridge to the game recipient."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('connected_notification',HERE/'replay-socket-ready-notification.py')
notification=importlib.util.module_from_spec(spec);spec.loader.exec_module(notification)
native,x=notification.native,notification.x
BIND_START,BIND_END=0x144aaae8d,0x144aaaf05
ALLOC,BRIDGE=0x1414276b0,0x14370c510
DELEGATE_TABLE,GAME_TABLE=0x14900a528,0x149d84e50
GAME_RECIPIENT=0x1467a9cd0


class Replay(notification.Replay):
    def __init__(self,raw,image,fragments,completion,handle,option_body,extra,leaves,delegate_fragments,delegate_leaves,fixture):
        super().__init__(raw,image,fragments,completion,handle,option_body,extra,leaves,fixture)
        rows=[r for f in delegate_fragments if f['root_begin_rva']+image.pe.base in (0x144aaadb0,ALLOC,BRIDGE) for r in f['instructions']]
        rows += [r for f in delegate_leaves for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        self.delegate_hooks={0x1414311c0,0x141429520,GAME_RECIPIENT}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in (*self.delegate_hooks,DELEGATE_TABLE,GAME_TABLE,BIND_END))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.wrapper=self.allocate(0x190)
        self.uc.mem_write(self.wrapper,struct.pack('<Q',GAME_TABLE))
        self.uc.mem_write(self.wrapper+0x10,struct.pack('<Q',self.peer))
        self.uc.mem_write(self.peer+0x308,b'\0'*16)
        self.binding=False;self.bound_delegate=None

    def hook(self,uc,address,size,user):
        if address==BIND_END and getattr(self,'binding',False):
            uc.emu_stop();return
        if address==BRIDGE:
            self.events.append(dict(action='native_delegate_virtual60_entry'))
        if address==0x14370c552:
            self.events.append(dict(action='native_delegate_result',al=uc.reg_read(x.UC_X86_REG_RAX)&255))
        if address not in self.delegate_hooks:return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==0x1414311c0:
            if a!=self.peer+0x308 or b or c!=3 or d!=16:raise ValueError('Delegate allocation descriptor changed')
            result=0 if self.fixture['allocation_fail'] else self.allocate(c*d)
            uc.mem_write(a,struct.pack('<Q',result));self.bound_delegate=result
            self.events.append(dict(action='delegate_resize_fixture',units=c,unit_size=d,allocated=bool(result)))
        elif address==0x141429520:
            result=17  # Synthetic instance identity only, unused by invoke in this path.
        elif address==GAME_RECIPIENT:
            if a!=self.wrapper:raise ValueError('Game connection recipient this changed')
            self.events.append(dict(action='game_connected_recipient_capture',
                endpoint_descriptor=bytes(uc.mem_read(b,16)).hex(),returned=self.fixture['callback_return']))
            result=int(self.fixture['callback_return'])
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=int.from_bytes(uc.mem_read(rsp,8),'little')
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        # Execute constructor tail only. Peer and wrapper construction/startup
        # are fixtures; this is not an assertion that full constructors ran.
        self.binding=True
        self.uc.reg_write(x.UC_X86_REG_RSP,self.stack)
        self.uc.reg_write(x.UC_X86_REG_RBP,self.wrapper)
        self.uc.reg_write(x.UC_X86_REG_RDI,self.wrapper+0x10)
        self.uc.emu_start(BIND_START,self.stop,count=4096)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=BIND_END:raise ValueError('Delegate binding budget')
        self.binding=False
        descriptor=bytes(self.uc.mem_read(self.peer+0x308,16)).hex()
        bound=bytes(self.uc.mem_read(self.bound_delegate,0x30)).hex() if self.bound_delegate else None
        # Deliberate post-binding gate perturbations, not constructor outputs.
        if not self.fixture['owner_count']:self.uc.mem_write(self.peer+0x310,b'\0'*4)
        if not self.fixture['owner_present']:self.uc.mem_write(self.peer+0x308,b'\0'*8)
        result=super().capture()
        result.update(bound_descriptor=descriptor,bound_delegate=bound,
            wrapper_backpointer_matches=int.from_bytes(self.uc.mem_read(self.peer+0x230,8),'little')==self.wrapper,
            delegate_target_matches=bool(self.bound_delegate) and int.from_bytes(self.uc.mem_read(self.bound_delegate+0x18,8),'little')==self.wrapper)
        # Heap pointers are deterministic within each replay; bytes exported
        # above are synthetic values, never process memory or real identities.
        return result


def build():
    path=native.ROOT/'code-clues/socket-ready-notification-replay.json'
    prior=json.loads(path.read_text('utf-8'))
    upstream=json.loads((native.ROOT/'code-clues/socket-readiness-job-replay.json').read_text('utf-8'))
    opt=json.loads((native.ROOT/'code-clues/socket-error-option-replay.json').read_text('utf-8'))
    raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Connected delegate source changed')
    image=native.Image(raw)
    addresses=(0x144aaadb0,ALLOC,BRIDGE,0x1467a79e0,0x1467aa0e0,GAME_RECIPIENT)
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in addresses})
    rows={r['address']:r for f in fragments for r in f['instructions']}
    bindings=[]
    for address,mnemonic,operands in (
        (0x1467aa108,'call','0x144aaadb0'),
        (0x1467a7acb,'mov','qword ptr [rbx], rax'),
        (0x144aaaea4,'mov','qword ptr [rax + 0x230], rbp'),
        (0x144aaaeba,'add','rdx, 0x308'),
        (0x144aaaec9,'call','0x1414276b0'),
        (0x144aaaefa,'mov','qword ptr [rbx], rax'),
        (0x144aaaefd,'mov','qword ptr [rbx + 0x18], rbp'),
        (0x144aaaf01,'movups','xmmword ptr [rbx + 0x20], xmm0')):
        r=rows[address]
        if (r['mnemonic'],r['operands'])!=(mnemonic,operands):raise ValueError('Delegate binding instruction changed')
        bindings.append(r)
    for address,target in ((0x1467a7ac4,GAME_TABLE),(0x144aaaef3,DELEGATE_TABLE),(0x144aaaeab,0x1437113ec)):
        r=rows[address]
        if r['rip_references']!=[target]:raise ValueError('Delegate binding reference changed')
        bindings.append(r)
    cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
    leaves=[]
    for address,size in ((0x1437113ec,6),(0x14141cbc0,0x13)):
        off=image.offset(address-image.pe.base);content=raw[off:off+size];instructions=[]
        for i in cs.disasm(content,address):
            refs=[i.address+i.size+op.mem.disp for op in i.operands if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
            instructions.append(dict(address=i.address,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=refs))
        if sum(len(bytes.fromhex(r['bytes'])) for r in instructions)!=size:raise ValueError('Delegate leaf decode changed')
        leaves.append(dict(address=address,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest(),instructions=instructions))
    if leaves[0]['bytes']!='488b01ff6048':raise ValueError('Game virtual48 action changed')
    tables=[]
    for address,slot,target in ((DELEGATE_TABLE,0x60,BRIDGE),(GAME_TABLE,0x48,GAME_RECIPIENT),(GAME_TABLE,8,0x1467aa0e0)):
        off=image.offset(address-image.pe.base);content=raw[off:off+0x68]
        if struct.unpack_from('<Q',content,slot)[0]!=target:raise ValueError('Connected vtable target changed')
        tables.append(dict(address=address,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest(),verified_slot=slot,target=target))
    fixtures=[dict(c['fixture'],allocation_fail=False,callback_return=False) for c in prior['cases']]
    fixtures.extend([dict(fixtures[0],name='allocation-fail',allocation_fail=True),dict(fixtures[0],name='callback-true',callback_return=True)])
    args=(raw,image,upstream['fragments'],upstream['completion_leaf'],upstream['handle_leaf'],opt['option_body'],prior['fragments'],prior['leaves'],fragments,leaves)
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fragments=fragments,leaves=leaves,tables=tables,bindings=bindings,
        cases=[Replay(*args,f).capture() for f in fixtures],native_execution=True,network_ready=False,
        limitations=['Native constructor tail binds delegate; actual allocator wrapper/bridge/virtual48 action execute.',
            'Full constructors and startup not executed; synthetic wrapper vtable source-bound to game construction.',
            'Resize backend and instance identity getter fixtures; allocation failure deliberately synthetic.',
            'Game recipient 0x1467a9cd0 captured at entry; body, packet construction and Login not executed.',
            'Inherited endpoint getter false, empty endpoint callback only; prior syscall/scheduler/lifetime fixtures retained.',
            'No game launch/profile/process memory/credentials/network or Android execution.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/transport-connected-delegate-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
