"""Native Auth silent dispatcher through real delegate bridge into game AutoSignIn callback."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('silent_game_source',HERE/'replay-game-auto-sign-in-result.py')
game=importlib.util.module_from_spec(spec);spec.loader.exec_module(game)
dispatch=game.dispatch
native,x=game.native,game.x
SILENT_DISPATCH,THUNK,GAME_LEAF=0x1444e02e0,0x1444d8410,0x1456007b0


class Replay(dispatch.NativeBindingReplay):
    def __init__(self,raw,image,fragments,leaves,fixture):
        super().__init__(raw,image,fragments,dict(bound=True,refcounted=fixture['refcounted'],
                                                heap_storage=fixture['heap_storage'],execute_ok=True))
        roots=(SILENT_DISPATCH,THUNK,game.CALLBACK)
        rows=[r for f in fragments if f['root_begin_rva']+image.pe.base in roots for r in f['instructions']]
        rows += [r for leaf in leaves for r in leaf['instructions']]
        self.allowed.update(r['address'] for r in rows)
        targets=(0x14560ea40,0x1445f5330,0x14560f740,0x1454894b0,0x145601f30,
                 0x141421150,0x145616630,0x145614370)
        self.game_targets=set(targets)
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in targets)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.fixture=fixture
        # Source-bound final function marker; TFunction context/clone remain explicit fixtures.
        self.uc.mem_write(self.original+0x20,struct.pack('<Q',GAME_LEAF))
        descriptor=bytes(self.uc.mem_read(self.auth+0x98,16))
        self.uc.mem_write(self.auth+0x98,b'\0'*16)
        self.uc.mem_write(self.auth+0xa8,descriptor if fixture['bound'] else b'\0'*16)
        self.capture_object=self.allocate(16);self.owner=self.allocate(64);self.owner_ref=self.allocate(32)
        self.response=self.base+0x6000
        self.manager,self.manager_child=self.allocate(128),self.allocate(64)
        self.uc.mem_write(self.capture_object,struct.pack('<QQ',self.owner if fixture['owner'] else 0,
                                                       self.owner_ref if fixture['weak'] else 0))
        self.uc.mem_write(self.owner_ref+8,struct.pack('<II',fixture['strong'],4))
        self.uc.mem_write(self.response+4,struct.pack('<I',fixture['field_4']))
        self.uc.mem_write(self.response+12,struct.pack('<I',fixture['field_c']))
        self.uc.mem_write(self.response+0x28,struct.pack('<Q',fixture['status']))
        self.uc.mem_write(0x14b574aa8,struct.pack('<Q',self.manager))
        self.uc.mem_write(self.manager+0x58,struct.pack('<Q',self.manager_child))
        self.context=self.capture_object
        self.events=[]

    def hook(self,uc,address,size,user):
        if address==0x1444d8430:
            self.events.append(dict(action='native_silent_delegate_return',al=uc.reg_read(x.UC_X86_REG_RAX)&255))
        if address==GAME_LEAF:
            a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
            if a!=self.capture_object or bytes(uc.mem_read(b,16))!=bytes(uc.mem_read(self.shared,16)):
                raise ValueError('Real game callback arguments changed')
            self.events.append(dict(action='native_game_callback_entry',original_response_pair=True))
        if address in self.allowed:return
        if address==0x14560ea40:
            a,b,c=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
            if a!=self.owner or bytes(uc.mem_read(b,16))!=bytes(uc.mem_read(self.shared,16)) or c&255!=9:
                raise ValueError('Game result logging pair changed')
            self.events.append(dict(action='result_log_capture',selector=9))
            uc.reg_write(x.UC_X86_REG_RAX,0)
            rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
            uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)
            return
        if address in getattr(self,'game_targets',()):return game.Replay.hook(self,uc,address,size,user)
        if address==0x141404350:
            a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
            thunk=struct.unpack('<Q',bytes(uc.mem_read(b,8)))[0]
            closure=struct.unpack('<Q',bytes(uc.mem_read(b+16,8)))[0]
            if a!=1 or thunk!=THUNK or closure!=self.allocations[-1]:raise ValueError('Silent task descriptor changed')
            self.queued=(thunk,closure+8)
            uc.mem_write(b,b'\0'*8);uc.mem_write(b+16,b'\0'*8)
            self.events.append(dict(action='silent_task_schedule_capture',selector=a,thunk=thunk))
            uc.reg_write(x.UC_X86_REG_RAX,0)
            rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
            uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)
            return
        return super().hook(uc,address,size,user)

    def capture(self):
        self.run(SILENT_DISPATCH,self.auth,self.shared)
        cleared=int.from_bytes(self.uc.mem_read(self.auth+0xb0,4),'little')==0
        count=int.from_bytes(self.uc.mem_read(self.ref+8,4),'little')
        thunk,payload=self.queued
        preserved=bytes(self.uc.mem_read(payload+0x18,16))==bytes(self.uc.mem_read(self.shared,16))
        self.events.append(dict(action='fixture_task_drain'))
        self.run(thunk,payload)
        return dict(fixture=self.fixture,original_delegate_cleared=cleared,response_pair_preserved=preserved,
                    response_strong_after_dispatch=count,
                    response_strong_after_thunk=int.from_bytes(self.uc.mem_read(self.ref+8,4),'little'),
                    owner_strong_after=int.from_bytes(self.uc.mem_read(self.owner_ref+8,4),'little'),events=self.events)


def build():
    gp=native.ROOT/'code-clues/game-auto-sign-in-result-replay.json'
    dp=native.ROOT/'code-clues/sdk-result-dispatch-replay.json'
    hp=native.ROOT/'code-clues/channel-silent-handoff-replay.json'
    prior=json.loads(gp.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Silent game source changed')
    image=native.Image(raw)
    addresses=(SILENT_DISPATCH,THUNK,game.CALLBACK,dispatch.DISPATCH,dispatch.THUNK,
               0x1414203f0,0x1444bee50,0x1444ba4f0,0x144237840,0x14423aaf0,0x1444cdb30)
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in addresses})
    handoff=json.loads(hp.read_text('utf-8'))
    if handoff['sha256']!=prior['sha256']:raise ValueError('Silent request source changed')
    request_rows=[r for f in handoff['fragments'] for r in f['instructions'] if 0x1444fe503<=r['address']<=0x1444fe530]
    for row in request_rows:
        off=image.offset(row['address']-image.pe.base)
        if raw[off:off+len(bytes.fromhex(row['bytes']))].hex()!=row['bytes']:
            raise ValueError('Silent request callback changed')
    address=0x1444d8610;off=image.offset(address-image.pe.base)
    content=raw[off:off+5]
    if content[:1]!=b'\xe9' or address+5+struct.unpack('<i',content[1:])[0]!=0x1444cdb30:
        raise ValueError('Silent response jump leaf changed')
    response_jump=dict(address=address,file_offset=off,bytes=content.hex(),
                       sha256=hashlib.sha256(content).hexdigest(),target=0x1444cdb30)
    leaves=prior['leaves']
    for leaf in leaves:
        off=image.offset(leaf['address']-image.pe.base)
        if raw[off:off+len(bytes.fromhex(leaf['bytes']))].hex()!=leaf['bytes']:
            raise ValueError('Game leaf source changed')
    literals=[]
    for f in fragments:
        if f['root_begin_rva']!=SILENT_DISPATCH-image.pe.base:continue
        for row in f['instructions']:
            for ref in row['rip_references']:
                if lit:=dispatch.completion.gates.fields.lifecycle.guid.source.config.read_literal(raw,image,ref):
                    literals.append(dict(instruction=row['address'],**lit))
    base=dict(bound=True,owner=True,weak=True,strong=4,field_4=0,field_c=0,status=200)
    profiles=[dict(base,name='success'),dict(base,name='no-binding',bound=False),dict(base,name='expired',strong=0),
              dict(base,name='no-owner',owner=False),dict(base,name='ordinary-error',field_4=1,field_c=7),
              dict(base,name='special-429',field_4=1,field_c=40040011,status=429)]
    cases=[]
    for profile in profiles:
        for refcounted,heap in ((False,False),(True,True)):
            fixture=dict(profile,refcounted=refcounted,heap_storage=heap)
            cases.append(Replay(raw,image,fragments,leaves,fixture).capture())
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                upstream_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (gp,dp,hp)},
                fragments=fragments,leaves=leaves,literals=literals,
                request_callback_instructions=request_rows,response_jump=response_jump,cases=cases,native_execution=True,network_ready=False,
                limitations=[
                    'Native silent dispatcher, clone/invoke bridge, queued thunk and actual game leaf/callback execute together.',
                    'Auth response callback is static evidence only; native JSON/status/errorCode/session processing not replayed here.',
                    'Bound game leaf is source-linked through prior game descriptor and channel handoff; storage acquisition/copy is fixture.',
                    'TFunction clone/get-context, allocation/destruction and scheduler move/drain remain fixtures/captures.',
                    'Game logging/manager/fallback actions captured; success game-instance getter is null fixture.',
                    'Response final destruction, real task graph/threads/races/active service startup and game Login remain unverified.',
                    'No game launch, process memory, profile, credentials or HTTP used.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/silent-game-dispatch-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
