"""Native game AutoSignIn callback gates; opaque external effects are captures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('auto_dispatch',HERE/'replay-sdk-result-dispatch.py')
dispatch=importlib.util.module_from_spec(spec);spec.loader.exec_module(dispatch)
native,x=dispatch.native,dispatch.x
CALLBACK=0x1455fbb80


class Replay(dispatch.Replay):
    def __init__(self,raw,image,fragments,leaves,fixture):
        super().__init__(raw,image,fragments,dict(bound=False,refcounted=False,execute_ok=False))
        rows=[r for f in fragments if f['root_begin_rva']==CALLBACK-image.pe.base for r in f['instructions']]
        rows += [r for f in leaves for r in f['instructions']]
        self.allowed={r['address'] for r in rows}
        self.targets={0x14560ea40,0x1445f5330,0x14560f740,0x1454894b0,0x145601f30,
                      0x141421150,0x145616630,0x14147d580,0x145614370}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in self.targets)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.fixture=fixture
        self.capture_object=self.base+0xb000
        self.owner,self.owner_ref,self.response=self.base+0xc000,self.base+0xd000,self.base+0xe000
        self.manager,self.manager_child=self.base+0xf000,self.base+0x8000
        self.uc.mem_write(self.capture_object,struct.pack('<QQ',self.owner if fixture['owner'] else 0,
                                                       self.owner_ref if fixture['weak'] else 0))
        self.uc.mem_write(self.owner_ref+8,struct.pack('<II',fixture['strong'],4))
        self.uc.mem_write(self.shared,struct.pack('<QQ',self.response,0))
        self.uc.mem_write(self.response+4,struct.pack('<I',fixture['field_4']))
        self.uc.mem_write(self.response+12,struct.pack('<I',fixture['field_c']))
        self.uc.mem_write(self.response+0x28,struct.pack('<Q',fixture['status']))
        self.uc.mem_write(0x14b574aa8,struct.pack('<Q',self.manager))
        self.uc.mem_write(self.manager+0x58,struct.pack('<Q',self.manager_child))
        self.events=[]

    def hook(self,uc,address,size,user):
        if address in self.allowed:return
        a,b,c=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        result=0
        if address==0x14560ea40:
            if a!=self.owner or b!=self.shared or c&255!=9:raise ValueError('Result logging arguments changed')
            self.events.append(dict(action='result_log_capture',selector=9))
        elif address==0x1445f5330:
            pointer=struct.unpack('<Q',bytes(uc.mem_read(b,8)))[0]
            self.events.append(dict(action='manager_action_capture',target_pointer=pointer))
        elif address==0x14560f740:
            if a!=self.manager_child:raise ValueError('Manager child changed')
            self.events.append(dict(action='manager_child_capture',target=address))
        elif address==0x1454894b0:
            # Empty game-instance fixture bounds the success branch before its extra callback.
            self.events.append(dict(action='game_instance_getter_fixture',returned_null=True))
        elif address==0x145601f30:
            uc.mem_write(b,b'\0'*16);result=b
            self.events.append(dict(action='error_text_capture',target=address))
        elif address==0x141421150:
            uc.mem_write(a,b'\0'*16);result=a
        elif address==0x145616630:
            self.events.append(dict(action='error_action_capture',target=address,flag=b&255))
        elif address==0x145614370:
            self.events.append(dict(action='fallback_capture',target=address))
        elif address==0x14147d580:pass
        else:raise ValueError('Unexpected game callback execution '+hex(address))
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        self.run(CALLBACK,self.capture_object,self.shared)
        return dict(fixture=self.fixture,events=self.events,
                    strong_after=int.from_bytes(self.uc.mem_read(self.owner_ref+8,4),'little'))


def build():
    path=native.ROOT/'code-clues/sdk-result-dispatch-replay.json'
    prior=json.loads(path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Game callback source changed')
    image=native.Image(raw)
    roots=(dispatch.DISPATCH,CALLBACK,0x145600460,0x1455f7bd0,0x144521550,0x1444fea30,0x1444feac0,0x145614370)
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in roots})
    cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
    leaves=[]
    for a in (0x1456007b0,0x14452b040,0x141a273d0,0x140ba0b90,0x1418089f0):
        off=image.offset(a-image.pe.base);rows=[]
        for i in cs.disasm(raw[off:off+32],a):
            refs=[i.address+i.size+op.mem.disp for op in i.operands
                  if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
            rows.append(dict(address=i.address,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=refs))
            if i.mnemonic in ('ret','jmp'):break
        content=b''.join(bytes.fromhex(r['bytes']) for r in rows)
        leaves.append(dict(address=a,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest(),instructions=rows))
    literal=dispatch.completion.gates.fields.lifecycle.guid.source.config.read_literal(raw,image,image.pe.address(0x98b6590))
    refs=native.rip_candidates(image,{image.pe.address(0x98b6590),0x1456007b0})
    decoded={r['address']:r for f in fragments for r in f['instructions']}
    verified=[dict(instruction=decoded[a],target=t) for a,t in refs if a in decoded and t in decoded[a]['rip_references']]
    route_diagnostics=[]
    for fragment in fragments:
        if fragment['root_begin_rva'] not in (0x4521550,0x44feac0):continue
        for row in fragment['instructions']:
            for ref in row['rip_references']:
                lit=dispatch.completion.gates.fields.lifecycle.guid.source.config.read_literal(raw,image,ref)
                if lit and ('FServiceImpl::GetChannelManager(' in lit['text'] or 'FChannelManagerImpl::SignInSilently(' in lit['text']):
                    route_diagnostics.append(dict(instruction=row,root=fragment['root_begin_rva']+image.pe.base,literal=lit))
    if len(route_diagnostics)!=2:raise ValueError('Channel manager route diagnostics changed')
    fixtures=[]
    base=dict(owner=True,weak=True,strong=4,field_4=0,field_c=0,status=200)
    for label,changes in [('success',{}),('no-weak',dict(weak=False)),('expired',dict(strong=0)),('no-owner',dict(owner=False))]:
        fixtures.append(dict(base,name=label,**changes))
    for code in (0x262f64b,0x1ca86dc):
        for status in (429,502,200):
            fixtures.append(dict(base,name='special-'+str(code)+'-'+str(status),field_4=1,field_c=code,status=status))
    for status in (1100,1202,1210,200):
        fixtures.append(dict(base,name='fallback-status-'+str(status),field_4=0x1ca86f7,status=status))
    fixtures.append(dict(base,name='ordinary-error',field_4=1,field_c=7))
    cases=[Replay(raw,image,fragments,leaves,f).capture() for f in fixtures]
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dispatch_report_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),fragments=fragments,
                leaves=leaves,diagnostic=literal,route_diagnostics=route_diagnostics,verified_xrefs=verified,cases=cases,native_execution=True,network_ready=False,
                limitations=[
                    'AutoSignIn naming is a source diagnostic through verified logging callback; no direct connection to auth SignIn dispatcher claimed.',
                    'Game caller uses getter owner+0x170 and wrapper 0x1444fea30, source diagnostics bind GetChannelManager and SignInSilently, distinct from GetAuth owner+0x150.',
                    'Native callback weak-owner gates and raw result field branches execute; logging/manager/error/fallback actions are captures.',
                    'Success game-instance getter returns null fixture; downstream virtual callback and full game Login are not executed.',
                    'No meanings invented for numeric errors, manager action pointers, thread affinity or active route.',
                    'No game launch, process memory, profiles, credentials or HTTP used.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/game-auto-sign-in-result-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
