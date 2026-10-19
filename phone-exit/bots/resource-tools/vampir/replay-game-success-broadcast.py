"""Native silent/game success broadcast into source-bound title interface slot 0x30."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('success_silent',HERE/'replay-silent-game-dispatch.py')
silent=importlib.util.module_from_spec(spec);spec.loader.exec_module(silent)
native,x=silent.native,silent.x
BROADCAST,ACTION,TITLE=0x1445f5330,0x143b8bf10,0x14641dbc0
TITLE_TABLE=0x149c4cda0


class Replay(silent.Replay):
    def __init__(self,raw,image,fragments,leaves,fixture):
        super().__init__(raw,image,fragments,leaves,dict(bound=True,owner=True,weak=True,strong=4,
            field_4=0,field_c=0,status=200,refcounted=True,heap_storage=True))
        self.broadcast_fixture=fixture
        rows=[r for f in fragments if f['root_begin_rva']+image.pe.base in (BROADCAST,TITLE) for r in f['instructions']]
        rows += [r for leaf in leaves if leaf['address']==ACTION for r in leaf['instructions']]
        self.allowed.update(r['address'] for r in rows)
        targets=(0x1414315f0,0x1445baf60,0x1445ce290,0x1445bb240,0x300000a0,0x148796040)
        self.broadcast_targets=set(targets)
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in (*targets,TITLE_TABLE))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.subscribers=[];self.subscriber_counts=[];self.windows=[]
        self.window_vtable=self.allocate(0x600)
        self.uc.mem_write(self.window_vtable+0x598,struct.pack('<Q',0x300000a0))
        items=self.allocate(max(32,len(fixture['subscribers'])*32))
        for n,kind in enumerate(fixture['subscribers']):
            # Only title interface subobject and accessed field are needed; full UObject not constructed.
            listener=self.allocate(0x280);ref=self.allocate(32)
            self.uc.mem_write(listener,struct.pack('<Q',TITLE_TABLE))
            window=self.allocate(32)
            self.windows.append(window)
            self.uc.mem_write(window,struct.pack('<Q',self.window_vtable))
            self.uc.mem_write(listener+0x228,struct.pack('<Q',window if fixture['window_present'] else 0))
            strong=0 if kind=='expired' else 4
            self.uc.mem_write(ref+8,struct.pack('<II',strong,4))
            self.subscribers.append(listener)
            self.subscriber_counts.append((ref,strong))
            self.uc.mem_write(items+n*32,struct.pack('<QQQQ',0 if kind=='null' else listener,ref,0,0))
        self.uc.mem_write(self.manager+0x10,struct.pack('<QII',items,len(fixture['subscribers']),len(fixture['subscribers'])))
        self.events=[]

    def hook(self,uc,address,size,user):
        if address==TITLE:
            listener=uc.reg_read(x.UC_X86_REG_RCX)
            if listener not in self.subscribers:raise ValueError('Title subscriber changed')
            self.events.append(dict(action='native_title_slot30_entry',subscriber=self.subscribers.index(listener)))
        if address in self.allowed:return super().hook(uc,address,size,user)
        if address not in getattr(self,'broadcast_targets',()):return super().hook(uc,address,size,user)
        a,b,c=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        result=0
        if address==0x1414315f0:
            if not 1<=b<=8:raise ValueError('Broadcast array bound')
            count=int.from_bytes(uc.mem_read(a+8,4),'little')
            ptr=self.allocate(b*32);uc.mem_write(a,struct.pack('<QII',ptr,count,b))
        elif address==0x1445baf60:
            if not 1<=c<=8:raise ValueError('Broadcast copy bound')
            uc.mem_write(a,bytes(uc.mem_read(b,c*32)))
            self.events.append(dict(action='subscriber_array_copy_fixture',count=c))
        elif address==0x1445ce290:
            self.events.append(dict(action='subscriber_prune_capture'))
        elif address==0x1445bb240:
            self.events.append(dict(action='subscriber_array_destroy_capture',count=b))
        elif address==0x300000a0:
            if a not in self.windows or b!=2 or c&255!=1:raise ValueError('Title child virtual call changed')
            self.events.append(dict(action='title_child_virtual_capture',subscriber=self.windows.index(a),slot=0x598,arg_edx=b,arg_r8b=c&255))
        elif address==0x148796040:pass
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        result=super().capture()
        result['fixture']=self.broadcast_fixture
        result['title_child_cleared']=[int.from_bytes(self.uc.mem_read(p+0x228,8),'little')==0 for p in self.subscribers]
        result['subscriber_strong_after']=[int.from_bytes(self.uc.mem_read(ref+8,4),'little') for ref,count in self.subscriber_counts]
        return result


def build():
    path=native.ROOT/'code-clues/silent-game-dispatch-replay.json'
    prior=json.loads(path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Broadcast source changed')
    image=native.Image(raw)
    roots={image.roots[image.containing(a)] for a in (BROADCAST,TITLE,0x14640a5f0,0x14640f800)}
    fragments=prior['fragments']+native.decode_ranges(image,roots)
    cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
    off=image.offset(ACTION-image.pe.base);rows=[]
    for i in cs.disasm(raw[off:off+16],ACTION):
        rows.append(dict(address=i.address,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=[]))
        if i.mnemonic=='jmp':break
    if rows[-1]['operands']!='qword ptr [rax + 0x30]':raise ValueError('Success action slot changed')
    content=b''.join(bytes.fromhex(r['bytes']) for r in rows)
    leaf=dict(address=ACTION,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest(),instructions=rows)
    leaves=prior['leaves']+[leaf]
    offset=image.offset(TITLE_TABLE-image.pe.base);table=raw[offset:offset+56]
    if struct.unpack_from('<Q',table,0x30)[0]!=TITLE:raise ValueError('Title slot 30 changed')
    constructors=[r for f in fragments if f['root_begin_rva'] in (0x640a5f0,0x640f800) for r in f['instructions']
                  if TITLE_TABLE in r['rip_references']]
    if len(constructors)!=2:raise ValueError('Title interface construction source changed')
    profiles=[dict(name='empty',subscribers=[]),dict(name='live',subscribers=['live']),
              dict(name='expired',subscribers=['expired']),dict(name='null',subscribers=['null']),
              dict(name='mixed',subscribers=['expired','live','null','live']),
              dict(name='two-live',subscribers=['live','live'])]
    profiles=[dict(p,window_present=present) for p in profiles for present in (False,True)]
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),fragments=fragments,leaves=leaves,
                title_vtable=dict(address=TITLE_TABLE,file_offset=offset,bytes=table.hex(),sha256=hashlib.sha256(table).hexdigest()),
                title_constructor_leas=constructors,cases=[Replay(raw,image,fragments,leaves,f).capture() for f in profiles],
                native_execution=True,network_ready=False,limitations=[
                    'Native silent/game callback chain now executes success broadcast, action virtual slot30 and title handler initial branch.',
                    'Subscriber registration and actual active list unknown; list and title interface subobjects are fixtures using source-bound vtable.',
                    'Array allocation/copy/destruction are fixtures/captures; full weak-copy lifecycle and concurrent subscriber mutation not verified.',
                    'Prune is a capture; no claim actual source list was modified.',
                    'Title handler calls child virtual+0x598 with EDX2/R8B1 and clears field+0x228; child target is a capture.',
                    'No direct packet Login, real session, complete title UObject/startup or network proof.',
                    'No game launch/process memory/profile/credentials/HTTP used.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/game-success-broadcast-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
