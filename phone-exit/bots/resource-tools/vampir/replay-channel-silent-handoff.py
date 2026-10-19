"""Native ChannelManager silent handoff to Auth; context/storage/callback fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('handoff_dispatch',HERE/'replay-sdk-result-dispatch.py')
dispatch=importlib.util.module_from_spec(spec);spec.loader.exec_module(dispatch)
native,x=dispatch.native,dispatch.x
BEGIN=0x1444feac0
STOPS=(0x1444feb71,0x1444fec88)
AUTH_STOPS=(0x1444fdde4,0x1444fdf0d,0x1444fdfea)
CLONE,RELEASE=0x30000080,0x30000090


class Replay(dispatch.Replay):
    def __init__(self,raw,image,fragments,leaf,fixture):
        super().__init__(raw,image,fragments,dict(bound=False,refcounted=False,execute_ok=False))
        self.stage="channel"
        rows=[r for f in fragments if f['root_begin_rva'] in (0x44feac0,0x45209e0,0x44fdd00) for r in f['instructions']]
        rows+=leaf['instructions']
        self.allowed={r['address'] for r in rows}
        self.targets={0x1444ba4f0,0x144523ff0,0x144525630,0x1444aacb0,0x144524d80,0x1444fdd00,0x14147d580}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in self.targets)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.fixture=fixture
        self.channel,self.function,self.storage_vtable=self.base+0xb000,self.base+0xc000,self.base+0xd000
        self.settings_class,self.settings,self.service,self.context=self.base+0xe000,self.base+0xf000,self.base+0x8000,self.base+0x9000
        self.auth_impl=self.base+0x6000
        self.uc.mem_write(self.service,struct.pack('<Q',self.context))
        self.uc.mem_write(self.context+0x150,struct.pack('<Q',self.auth_impl))
        self.uc.mem_write(self.settings_class+0x110,struct.pack('<Q',self.settings))
        self.uc.mem_write(self.storage_vtable,struct.pack('<Q',CLONE))
        self.uc.mem_write(self.storage_vtable+0x10,struct.pack('<Q',RELEASE))
        if fixture['callback']:
            self.uc.mem_write(self.function,struct.pack('<Q',0x11223344))
            storage=self.allocate(16) if fixture['heap_storage'] else self.function+0x20
            self.uc.mem_write(storage,struct.pack('<Q',self.storage_vtable))
            self.uc.mem_write(self.function+0x10,struct.pack('<Q',storage if fixture['heap_storage'] else 0))
        self.uc.mem_write(0x14b4f13f8,bytes([fixture['supported']]))
        self.events=[]

    def hook(self,uc,address,size,user):
        if address in (*STOPS,*AUTH_STOPS):
            self.events.append(dict(action='research_error_stop',address=address));uc.emu_stop();return
        if address in self.allowed and not (address==0x1444fdd00 and self.stage=="channel"):return
        a,b,c=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        result=0
        if address==0x1444ba4f0:
            offset=0xd0 if self.stage=='channel' else 0xa8
            owner=self.channel if self.stage=='channel' else self.auth_impl
            if a!=owner+offset or b!=self.function:raise ValueError('Callback binding changed')
            self.events.append(dict(action='callback_binding_capture',offset=offset))
        elif address==0x144523ff0:result=self.service
        elif address==0x144525630:
            if b!=self.context:raise ValueError('Service context changed')
            uc.mem_write(a,struct.pack('<QQ',self.service if self.fixture['initialized'] else 0,0));result=a
        elif address==0x1444aacb0:result=self.settings_class
        elif address==0x144524d80:
            if a!=self.settings:raise ValueError('Settings CDO changed')
            data=(self.fixture['player_id']+'\0').encode('utf-16le');ptr=self.allocate(len(data))
            uc.mem_write(ptr,data);uc.mem_write(b,struct.pack('<QII',ptr,len(data)//2,len(data)//2));result=b
            self.events.append(dict(action='stored_player_fixture',value=self.fixture['player_id']))
        elif address==CLONE:
            ptr=self.allocate(16);uc.mem_write(ptr,struct.pack('<Q',self.storage_vtable))
            uc.mem_write(b,struct.pack('<Q',ptr));result=ptr
            self.events.append(dict(action='function_clone_fixture'))
        elif address==RELEASE:self.events.append(dict(action='function_release_capture'))
        elif address==0x1444fdd00:
            if a!=self.auth_impl:raise ValueError('Auth impl route changed')
            ptr,count,capacity=struct.unpack('<QII',bytes(uc.mem_read(b,16)))
            player=bytes(uc.mem_read(ptr,count*2)).decode('utf-16le')[:-1]
            callback=struct.unpack('<Q',bytes(uc.mem_read(c,8)))[0]
            self.events.append(dict(action='auth_silent_capture',player_id=player,callback_marker=callback))
        elif address==0x14147d580:pass
        else:raise ValueError('Unexpected channel handoff instruction '+hex(address))
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        self.uc.mem_write(self.stack,struct.pack('<Q',self.stop))
        for reg,value in ((x.UC_X86_REG_RSP,self.stack),(x.UC_X86_REG_RCX,self.channel),(x.UC_X86_REG_RDX,self.function)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(BEGIN,self.stop,count=4096)
        rip=self.uc.reg_read(x.UC_X86_REG_RIP)
        if rip not in (*STOPS,self.stop):raise ValueError('Handoff execution budget')
        return dict(fixture=self.fixture,events=self.events,stop_address=rip,
                    returned_al=(self.uc.reg_read(x.UC_X86_REG_RAX)&255) if rip==self.stop else None)


    def capture_auth_gate(self):
        self.stage='auth'
        descriptor=self.allocate(16)
        data=(self.fixture['player_id']+'\0').encode('utf-16le');pointer=self.allocate(len(data))
        self.uc.mem_write(pointer,data)
        self.uc.mem_write(descriptor,struct.pack('<QII',pointer,len(data)//2,len(data)//2))
        self.uc.mem_write(self.stack,struct.pack('<Q',self.stop))
        for reg,value in ((x.UC_X86_REG_RSP,self.stack),(x.UC_X86_REG_RCX,self.auth_impl),
                          (x.UC_X86_REG_RDX,descriptor),(x.UC_X86_REG_R8,self.function)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(0x1444fdd00,self.stop,count=4096)
        rip=self.uc.reg_read(x.UC_X86_REG_RIP)
        if rip not in AUTH_STOPS:raise ValueError('Auth gate budget or boundary changed')
        return dict(fixture=self.fixture,stop_address=rip,events=self.events)


def build():
    path=native.ROOT/'code-clues/game-auto-sign-in-result-replay.json'
    prior=json.loads(path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Handoff source changed')
    image=native.Image(raw)
    addresses=(BEGIN,0x1445209e0,dispatch.DISPATCH,0x1444fdd00)
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in addresses})
    cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
    address=0x144517ef0;off=image.offset(address-image.pe.base);rows=[]
    for i in cs.disasm(raw[off:off+32],address):
        refs=[i.address+i.size+op.mem.disp for op in i.operands if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
        rows.append(dict(address=i.address,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=refs))
        if i.mnemonic=='ret':break
    content=b''.join(bytes.fromhex(r['bytes']) for r in rows)
    leaf=dict(address=address,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest(),instructions=rows)
    if rows[0]['rip_references']!=[0x14b4f13f8]:raise ValueError('Support byte source changed')
    literals=[]
    for f in fragments:
        for row in f['instructions']:
            for ref in row['rip_references']:
                lit=dispatch.completion.gates.fields.lifecycle.guid.source.config.read_literal(raw,image,ref)
                if lit:literals.append(dict(instruction=row['address'],**lit))
    base=dict(supported=True,initialized=True,callback=True,heap_storage=False,player_id='player-fixture')
    fixtures=[dict(base,name='unsupported',supported=False),dict(base,name='uninitialized',initialized=False)]
    for callback,heap in ((False,False),(True,False),(True,True)):
        for player in ('','player-fixture'):
            fixtures.append(dict(base,name=f'forward-{callback}-{heap}-{bool(player)}',callback=callback,heap_storage=heap,player_id=player))
    auth_fixtures=[dict(base,name='auth-uninitialized',initialized=False),
                   dict(base,name='auth-empty',player_id=''),dict(base,name='auth-single',player_id='x'),
                   dict(base,name='auth-player',player_id='player-fixture')]
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                game_report_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),fragments=fragments,
                support_leaf=leaf,literals=literals,
                auth_gate_cases=[Replay(raw,image,fragments,leaf,f).capture_auth_gate() for f in auth_fixtures],cases=[Replay(raw,image,fragments,leaf,f).capture() for f in fixtures],
                native_execution=True,network_ready=False,limitations=[
                    'ChannelManager::SignInSilently and native support-byte/GetAuth getters execute.',
                    'Settings CDO/stored player ID, service context, channel binding and TFunction clone/release remain fixtures.',
                    'Channel handoff captures Auth::SignInSilently call; separate auth_gate_cases execute its entry/init/player-length gates.',
                    'Auth request body/HTTP/error dispatch after gate stops are not executed.',
                    'Unsupported/uninitialized paths stop before native error object allocation, not full error callbacks.',
                    'Forwarded empty player ID can return true at ChannelManager level; downstream acceptance not proven.',
                    'Support byte active initialization/provider selection and first login without saved profile remain unknown.',
                    'No real credentials/storage/HTTP/game execution or process memory used.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/channel-silent-handoff-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases'])+len(report['auth_gate_cases']))))
