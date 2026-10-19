"""Native Login constructor/field assignment and cached SDK accessor branches."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('login_base',HERE/'replay-sdk-result-dispatch.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
LOGIN,CTOR,END=0x1467a9700,0x1456d4c80,0x1467a9b0b
STRINGS=(0x10,0x20,0x30,0x40,0x58,0x68,0x78,0x88,0xa0,0xb8,0xc8,0xd8,0xe8,0x100,0x110)


class Replay(base.Replay):
    def __init__(self,raw,image,fragments,leaves,fixture,globals_):
        super().__init__(raw,image,fragments,dict(bound=False,refcounted=False,execute_ok=False))
        self.fixture=fixture
        rows=[r for f in fragments for r in f['instructions']]+[r for f in leaves for r in f['instructions']]
        self.allowed={r['address'] for r in rows}
        self.targets={0x143c13690,0x141421150,0x1414596e0,0x14147d580,0x141420f70,0x1445c63a0,
            0x14143c260,0x1445c77a0,0x1414313d0,0x1487a2e19,0x145564550,0x145604bf0,
            0x145cb2f60,0x145cb95e0,0x144ff8cd0,0x144aa7c40,0x144aa8020,0x1416aaaf0,
            0x141424870,0x141420cc0,0x14142d840,0x144505520}
        pages={a&~4095 for r in rows for a in (r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references'])}
        pages.update(a&~4095 for a in (*self.targets,*globals_.values(),END,0x1498d6058))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.wrapper=self.allocate(0x190);self.peer=self.allocate(0x320)
        self.uc.mem_write(self.wrapper+0x10,struct.pack('<Q',self.peer))
        self.uc.mem_write(self.peer+0x270,struct.pack('<I',fixture['server_id']))
        for offset,value in ((0xe0,'wrapper-e0'),(0xf0,'wrapper-f0'),(0x100,'wrapper-100')):self.fwrite(self.wrapper+offset,value)
        self.service_module=self.allocate(0x120);self.service_settings=self.allocate(0x120)
        self.module=self.allocate(0x100);self.settings=self.allocate(0x500)
        self.manager=self.allocate(0x100);self.auth_context=self.allocate(0x80)
        self.fwrite(self.auth_context+0x58,fixture.get('cached_token',''))
        for global_name,obj in (('module_cache',self.service_module),('settings_cache',self.service_settings)):
            self.uc.mem_write(globals_[global_name],struct.pack('<Q',obj))
        self.uc.mem_write(self.service_module+0x110,struct.pack('<Q',self.module if fixture['module_present'] else 0))
        self.uc.mem_write(self.service_settings+0x110,struct.pack('<Q',self.settings if fixture['settings_present'] else 0))
        self.fwrite(self.module+0x78,fixture['sdk_token']);self.fwrite(self.settings+0x4a8,fixture['netmarble_id'])
        self.uc.mem_write(globals_['manager'],struct.pack('<Q',self.manager if fixture['manager_present'] else 0))
        for offset,value in ((0x38,self.auth_context if fixture['auth_present'] else 0),(0x48,self.manager),(0x68,self.manager)):
            self.uc.mem_write(self.manager+offset,struct.pack('<Q',value))
        self.uc.mem_write(globals_['sdk_enabled'],bytes([fixture['sdk_enabled']]))
        p=self.allocate(32);self.uc.mem_write(p,b'version-fixture\0')
        self.uc.mem_write(globals_['version'],struct.pack('<Q',p))
        self.uc.mem_write(globals_['enum'],struct.pack('<I',2))
        self.fwrite(globals_['text'],'global-text')
        self.uc.mem_write(globals_['number'],struct.pack('<I',123))
        self.policy=self.allocate(32);self.uc.mem_write(self.policy+0x18,b'\x07')
        self.request_manager=self.allocate(16);self.packet=None;self.events=[]

    def fwrite(self,desc,text):
        data=text.encode('utf-16le')+b'\0\0' if text else b''
        p=self.allocate(len(data)) if data else 0
        if data:self.uc.mem_write(p,data)
        self.uc.mem_write(desc,struct.pack('<QII',p,len(data)//2,len(data)//2))

    def fread(self,desc):
        p,n,cap=struct.unpack('<QII',bytes(self.uc.mem_read(desc,16)))
        if not 0<=n<=cap<=256 or (n and not p):raise ValueError('Login FString bound')
        if not n:return ''
        data=bytes(self.uc.mem_read(p,n*2))
        if not data.endswith(b'\0\0'):raise ValueError('Login FString terminator')
        return data[:-2].decode('utf-16le')

    def zread(self,p,encoding):
        unit=2 if encoding=='utf-16le' else 1;data=bytearray()
        for n in range(256):
            value=bytes(self.uc.mem_read(p+n*unit,unit))
            if value==b'\0'*unit:return data.decode(encoding)
            data.extend(value)
        raise ValueError('Login literal bound')

    def hook(self,uc,address,size,user):
        if address==END:uc.emu_stop();return
        if address in (CTOR,0x145604b90,0x1456039c0):self.events.append(dict(action='native_accessor_entry',address=address))
        if address in self.allowed:return
        if address not in self.targets:raise ValueError('Unexpected Login instruction '+hex(address))
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==0x143c13690:self.fwrite(a,self.fixture['platform'])
        elif address==0x141421150:self.fwrite(a,self.zread(b,'utf-16le'));result=a
        elif address==0x141420f70:self.fwrite(a,self.zread(b,'ascii'));result=a
        elif address==0x1414596e0:result=int(self.zread(a,'utf-16le')!=self.zread(b,'utf-16le'))
        elif address==0x1445c63a0:self.fwrite(a,'getter-c63a0');result=a
        elif address in (0x14143c260,0x141420cc0):self.fwrite(a,self.fread(b));result=a
        elif address==0x1445c77a0:result=self.fixture['selector']
        elif address==0x1414313d0:
            if not 0<=b<=256:raise ValueError('Login resize bound')
            count=int.from_bytes(uc.mem_read(a+8,4),'little');uc.mem_write(a,struct.pack('<QII',self.allocate(max(2,b*2)),count,b))
        elif address==0x1487a2e19:
            if c>512:raise ValueError('Login memcpy bound')
            uc.mem_write(a,bytes(uc.mem_read(b,c)));result=a
        elif address==0x145564550:result=self.policy
        elif address==0x145604bf0:self.fwrite(b,'collector-fixture');result=1
        elif address==0x145cb2f60:result=self.policy
        elif address==0x145cb95e0:result=1
        elif address==0x144ff8cd0:result=1
        elif address==0x1416aaaf0:self.events.append(dict(action='missing_sdk_object_init_capture'))
        elif address==0x141424870:
            if c>255:raise ValueError('Cached SDK token copy bound')
            self.fwrite(a,bytes(uc.mem_read(b,c*2)).decode('utf-16le'));result=a
        elif address==0x14142d840:uc.mem_write(a,b'\0'*16)
        elif address in (0x14147d580,0x144505520):pass
        elif address==0x144aa7c40:result=self.request_manager
        elif address==0x144aa8020:
            if a!=self.request_manager or c!=4:raise ValueError('Login request handoff args changed')
            rsp=uc.reg_read(x.UC_X86_REG_RSP)
            timeout=struct.unpack('<f',bytes(uc.mem_read(rsp+0x28,4)))[0]
            if timeout!=0:raise ValueError('Login handoff timeout fixture changed')
            if int.from_bytes(uc.mem_read(b,8),'little')!=0x1498d6058:raise ValueError('Login packet vtable changed')
            self.packet=dict(strings={hex(o):self.fread(b+o) for o in STRINGS},
                integers={hex(o):int.from_bytes(uc.mem_read(b+o,4),'little') for o in (0x50,0xb0,0xf8,0x120)},
                bytes={hex(o):int.from_bytes(uc.mem_read(b+o,1),'little') for o in (0x98,0x99,0x124,0x130,0x131)})
            self.events.append(dict(action='login_request_handoff_capture',raw_kind=c,raw_timeout=timeout))
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=int.from_bytes(uc.mem_read(rsp,8),'little')
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        self.uc.mem_write(self.stack,struct.pack('<Q',self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP,self.stack);self.uc.reg_write(x.UC_X86_REG_RCX,self.wrapper)
        self.uc.emu_start(LOGIN,self.stop,count=20000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=END or self.packet is None:raise ValueError('Login preparation budget')
        return dict(fixture=self.fixture,packet=self.packet,events=self.events)


def build():
    path=native.ROOT/'code-clues/version-result-handler-replay.json';prior=json.loads(path.read_text('utf-8'))
    raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Login source changed')
    image=native.Image(raw)
    addresses=(LOGIN,CTOR,0x145604b90,0x1456039c0,0x144524940,0x1444aab90,0x1444aacb0,0x1444bb470,base.DISPATCH)
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in addresses})
    rows={r['address']:r for f in fragments for r in f['instructions']}
    # All globals selected from decoded instruction operands.
    globals_={name:rows[address]['rip_references'][0] for name,address in (
        ('module_cache',0x1444aab97),('settings_cache',0x1444aacb7),('sdk_enabled',0x1467a996e),
        ('version',0x1456d4d53),('enum',0x1456d4d5f),('text',0x1467a9921),('number',0x1467a991b))}
    if rows[0x1467a9914]['rip_references']!=[globals_['text']+8]:raise ValueError('Login global FString count binding changed')
    cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
    leaves=[]
    for address,size in ((0x144aaaa10,11),(0x1456048a0,8)):
        off=image.offset(address-image.pe.base);data=raw[off:off+size];instructions=[]
        for i in cs.disasm(data,address):
            refs=[i.address+i.size+op.mem.disp for op in i.operands if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
            instructions.append(dict(address=i.address,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=refs))
        if sum(len(bytes.fromhex(r['bytes'])) for r in instructions)!=size or instructions[-1]['mnemonic']!='ret':raise ValueError('Login getter leaf changed')
        leaves.append(dict(address=address,file_offset=off,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest(),instructions=instructions))
    globals_['manager']=leaves[1]['instructions'][0]['rip_references'][0]
    diagnostics=[]
    for address,encoding,expected in ((0x1494e3a30,'ascii','GetNetmarbleId'),
        (rows[0x1467a9730]['rip_references'][0],'utf-16le','Android'),
        (rows[0x1467a9795]['rip_references'][0],'utf-16le','IOS')):
        off=image.offset(address-image.pe.base);unit=2 if encoding=='utf-16le' else 1;end=off
        while end-off<256 and raw[end:end+unit]!=b'\0'*unit:end+=unit
        data=raw[off:end+unit];text=data[:-unit].decode(encoding)
        if expected not in text:raise ValueError('Login diagnostic changed')
        diagnostics.append(dict(address=address,file_offset=off,bytes=data.hex(),text=text,encoding=encoding))
    if rows[0x144524962]['rip_references']!=[diagnostics[0]['address']]:raise ValueError('NetmarbleId diagnostic ref changed')
    base_fixture=dict(platform='Windows',selector=0,server_id=42,sdk_enabled=True,manager_present=True,auth_present=True,
        module_present=True,settings_present=True,sdk_token='sdk-token-fixture',netmarble_id='nid-fixture')
    fixtures=[dict(base_fixture,name='windows'),dict(base_fixture,name='android',platform='Android'),dict(base_fixture,name='ios',platform='IOS')]
    fixtures.extend(dict(base_fixture,name='selector-'+str(v),selector=v) for v in (1,2,3,4,5,255))
    fixtures.extend([dict(base_fixture,name='sdk-disabled',sdk_enabled=False),dict(base_fixture,name='manager-absent',manager_present=False),
        dict(base_fixture,name='auth-absent',auth_present=False),dict(base_fixture,name='module-absent',module_present=False),
        dict(base_fixture,name='settings-absent',settings_present=False),dict(base_fixture,name='empty-sdk-fields',sdk_token='',netmarble_id=''),
        dict(base_fixture,name='module-absent-old-cache',module_present=False,cached_token='old-cache-fixture')])
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fragments=fragments,leaves=leaves,globals=globals_,diagnostics=diagnostics,
        cases=[Replay(raw,image,fragments,leaves,f,globals_).capture() for f in fixtures],native_execution=True,network_ready=False,
        limitations=['Actual Login prefix/constructor/assignments, cached SDK getters/GetNetmarbleId/token accessor execute.',
            'Service caches/SDK state/wrapper/global values explicit fixtures; no real profile or generated identity.',
            'String constructors/copy/comparison/resize, collector/policy and init fallback helpers fixtures.',
            'Stops after request handoff capture before UI/post-send cleanup; writer/frame/network not executed.',
            'No full VersionResult-to-Login or SDK-response-to-Login replay; no game/credentials/network/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/login-packet-fields-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
