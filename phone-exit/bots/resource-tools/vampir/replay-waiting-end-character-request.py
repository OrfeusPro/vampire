"""Native WaitingEndNotify handler, selection predicate and CharacterList request."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('waiting_boundary',HERE/'replay-character-list-boundary.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
HANDLER,PREDICATE=0x146768540,0x145c85d90
PREDICATE_RESULT,SELECT,NEXT=0x30003000,0x30003010,0x30003020


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.wait_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in (HANDLER,PREDICATE,0x145d46400,0x1456b3360,0x1456e3ad0,0x14678ec40)})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.wait_fragments)
        self.wait_leaves=[]
        for a,length in ((0x144aaaab0,12),(0x1456048e0,8),(0x1456d54d0,22),(0x1456e2100,6)):
            off=self.image.offset(a-self.image.pe.base);data=self.raw[off:off+length]
            self.wait_leaves.append(dict(address=a,file_offset=off,bytes=data.hex()))
            self.ranges.append((a,a+length))
        self.wait_hooks={0x14142d840,0x141424430,0x145c8b1b0,0x144a21450,0x1463fc200,0x144a20390,
            0x145d37220,0x1445cbd50,0x1454f2ba0,PREDICATE_RESULT,SELECT,NEXT}
        rows=[r for f in self.wait_fragments for r in f['instructions']]
        refs=[a for r in rows for a in r['rip_references']]
        pages={p for begin,end in self.ranges for p in range(begin & ~4095,(end+4095) & ~4095,4096)}
        pages.update(a & ~4095 for a in (*refs,*self.wait_hooks,0x14b27eecb,0x14b574a90,0x149d811a0,0x1498d6b50))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])
        self.ctx=0x21000000;self.uc.mem_map(self.ctx,0x10000)

    def hook(self,uc,address,size,user):
        if address==PREDICATE:self.events.append(dict(action='native_selection_predicate'))
        if address not in self.wait_hooks:return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0;ctx=self.ctx
        if address==0x14142d840:uc.mem_write(a,bytes(16))
        elif address==0x141424430:pass
        elif address==0x145c8b1b0:self.events.append(dict(action='state_toggle_capture',value=b & 255))
        elif address==0x144a21450:result=ctx+0x7000
        elif address==0x1463fc200:result=ctx+0x7100
        elif address==0x144a20390:result=0  # UI lookup absent, never assumes UI is already visible.
        elif address==0x145d37220:result=ctx+0x4000
        elif address==0x1445cbd50:result=ctx+0x1000 if self.fixture['policy_object'] else 0
        elif address==0x1454f2ba0:result=ctx+0x2000
        elif address==PREDICATE_RESULT:
            if a!=ctx+0x1000:raise ValueError('Policy virtual this changed')
            result=self.fixture['policy_value'];self.events.append(dict(action='policy_virtual_capture',value=result))
        elif address==SELECT:
            if a!=ctx+0x5000:raise ValueError('Selection virtual this changed')
            self.events.append(dict(action='selection_virtual_capture',raw64=b,raw32=c & 0xffffffff))
        elif address==NEXT:
            if a!=ctx+0x5000:raise ValueError('Next virtual this changed')
            self.events.append(dict(action='next_virtual_capture'))
        uc.reg_write(x.UC_X86_REG_RAX,result)
        sp=uc.reg_read(x.UC_X86_REG_RSP);ret=int.from_bytes(uc.mem_read(sp,8),'little')
        uc.reg_write(x.UC_X86_REG_RSP,sp+8);uc.reg_write(x.UC_X86_REG_RIP,ret)

    def execute(self,fixture):
        self.fixture=fixture;self.events=[];self.heap=self.scratch+0x10000;self.object=self.scratch+0x1000
        ctx=self.ctx;self.uc.mem_write(ctx,bytes(0x10000))
        self.uc.mem_write(ctx+0x1000,struct.pack('<Q',ctx+0x3000))
        self.uc.mem_write(ctx+0x1010,struct.pack('<Q',ctx+0x2200))
        self.uc.mem_write(ctx+0x2230,struct.pack('<Q',ctx+0x2400))
        self.uc.mem_write(ctx+0x2238,struct.pack('<i',fixture['type_count']))
        self.uc.mem_write(ctx+0x2038,struct.pack('<i',1))
        self.uc.mem_write(ctx+0x2408,struct.pack('<Q',ctx+0x2030 if fixture['type_match'] else 0))
        self.uc.mem_write(ctx+0x3a18,struct.pack('<Q',PREDICATE_RESULT))
        self.uc.mem_write(ctx+0x5000,struct.pack('<Q',ctx+0x6000))
        self.uc.mem_write(ctx+0x6040,struct.pack('<Q',NEXT));self.uc.mem_write(ctx+0x6050,struct.pack('<Q',SELECT))
        self.uc.mem_write(0x14b574a90,struct.pack('<Q',ctx+0x5000))
        self.uc.mem_write(ctx+0x4028,struct.pack('<Q',fixture['selected_raw']))
        wrapper,table,peer=self.scratch+0x6000,self.scratch+0x7000,self.scratch+0x5000
        self.uc.mem_write(wrapper,struct.pack('<Q',table));self.uc.mem_write(wrapper+0x10,struct.pack('<Q',peer))
        self.uc.mem_write(table+0x38,struct.pack('<Q',base.SEND))
        self.uc.mem_write(peer+0x2a6,bytes([fixture['peer_flag']]))
        self.uc.mem_write(0x14b520d90,struct.pack('<Q',wrapper))
        self.uc.mem_write(0x14b27eecb,bytes([fixture['policy_disabled']]))
        packet=self.scratch+0x2000
        self.run(0x1456d54d0,packet)
        self.uc.mem_write(packet+0x10,struct.pack('<Q',0x0102030405060708))
        # Call the actual handler. Its third argument carries the notify object.
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000
        self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,ctx+0x8000),
            (x.UC_X86_REG_RDX,0x12345678),(x.UC_X86_REG_R8,packet)):self.uc.reg_write(reg,value)
        self.uc.emu_start(HANDLER,stop,count=100000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('WaitingEnd handler instruction budget')
        return dict(fixture=fixture,events=self.events.copy())


def build():
    path=native.ROOT/'code-clues/character-list-boundary-replay.json';prior=json.loads(path.read_text('utf-8'))
    em=Emulator()
    if prior['sha256']!=em.bindings['sha256']:raise ValueError('WaitingEnd source mismatch')
    sentinel_address=0x14961a378;off=em.image.offset(sentinel_address-em.image.pe.base)
    sentinel=struct.unpack_from('<Q',em.raw,off)[0]
    default=dict(peer_flag=0,policy_disabled=False,policy_object=True,type_count=1,type_match=True,policy_value=0,selected_raw=sentinel)
    cases=[]
    for peer in (0,1):
        for policy in (0,1,2,4):
            for selected in (sentinel,0x8877665544332211):
                cases.append(em.execute(dict(default,name=f'peer-{peer}-policy-{policy}-selected-{int(selected!=sentinel)}',
                    peer_flag=peer,policy_value=policy,selected_raw=selected)))
    for peer in (0,1):
        for update in (dict(name='disabled',policy_disabled=True),dict(name='no-object',policy_object=False),
            dict(name='bad-type-count',type_count=0),dict(name='type-mismatch',type_match=False)):
            cases.append(em.execute(dict(default,**dict(update,name=update['name']+'-peer-'+str(peer),peer_flag=peer))))
    anchors=[]
    for a,size in ((0x149d811a0,24),(0x1498d6b50,64),(sentinel_address,8),(0x14961a380,4)):
        off=em.image.offset(a-em.image.pe.base);anchors.append(dict(address=a,file_offset=off,bytes=em.raw[off:off+size].hex()))
    if struct.unpack_from('<Q',bytes.fromhex(anchors[0]['bytes']),16)[0]!=HANDLER:raise ValueError('WaitingEnd handler binding')
    rows={r['address']:r for f in em.wait_fragments for r in f['instructions']}
    if rows[0x14678f176]['rip_references']!=[0x149d811a0] or rows[0x14678f197].get('direct_target')!=0x1456d54d0 or rows[0x14678f1aa].get('direct_target')!=0x1467a7250:
        raise ValueError('WaitingEnd registration chain changed')
    if rows[0x14676864f].get('direct_target')!=0x145dbfe50:
        raise ValueError('WaitingEnd request tail jump changed')
    notify=bytes.fromhex(anchors[1]['bytes'])
    if struct.unpack_from('<Q',notify,0x28)[0]!=0x1456e2100 or struct.unpack_from('<Q',notify,0x20)[0]!=0x1456b3360:
        raise ValueError('WaitingEnd ID/reader slots changed')
    packet_id=em.run(0x1456e2100)
    if packet_id!=27:raise ValueError('WaitingEnd ID changed')
    literals=[]
    for a,expected in ((0x149d6a1e0,'PktWaitingEndNotifyHandler::OnHandler()'),(0x149d6a230,'SelecCharacter by QuickSelect')):
        data=(expected+'\0').encode('utf-16le');off=em.image.offset(a-em.image.pe.base)
        if em.raw[off:off+len(data)]!=data:raise ValueError('WaitingEnd diagnostic changed')
        literals.append(dict(address=a,file_offset=off,bytes=data.hex(),text=expected))
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fragments=em.wait_fragments,request_fragments=em.extra,leaves=em.wait_leaves,anchors=anchors,literals=literals,
        packet_id=packet_id,cases=cases,native_execution=True,network_ready=False,
        limitations=['Actual WaitingEndNotify constructor/handler/peer getter/selection predicate and requestB constructor-to-send run together.',
            'Policy lookup/type objects and virtual return are fixtures; UI lookup absent, send/selection/next backends captures.',
            'Notify body is synthetic raw64, not network input; factory registration static-bound only.',
            'Predicate fallback4 is native; returned values0/1/2/4 are fixture policy outputs, not proven enum names.',
            'No proven Login-to-WaitingEnd server lifecycle, ID101 frame/socket/response102/session/game/profile/network/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/waiting-end-character-request-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
