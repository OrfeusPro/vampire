"""Native SDK sign-in JSON caller preparation; getters/JSON/map remain explicit fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('signin_bootstrap',HERE/'build-headless-sdk-bootstrap-values.py')
bootstrap=importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)
config=bootstrap.settings.config
SEGMENTS=((0x1444fba4d,0x1444fbb65),(0x1444fbc88,0x1444fbdad))
GLOBAL_KEYS=(0x14b4f0a90,0x14b4f0a80,0x14b4f0af0,0x14b4f0b00,0x14b4f0aa0)
CTOR=0x1444bc380


class Replay:
    def __init__(self,raw,image,fragments,leaf,initializers):
        ping=bootstrap.settings.ping
        self.x=ping.x
        self.uc=ping.unicorn.Uc(ping.unicorn.UC_ARCH_X86,ping.unicorn.UC_MODE_64)
        self.base,self.stack,self.stop=0x20000000,0x20070000,0x2007f000
        self.uc.mem_map(self.base,0x80000)
        self.rbp=self.stack+0x100
        self.cursor=self.base+0x10000
        self.initializers=initializers
        self.allowed={i['address'] for f in fragments for i in f['instructions']
                      if f['root_begin_rva'] in initializers or f['root_begin_rva']==bootstrap.BUILD-image.pe.base
                      or any(a<=i['address']<b for a,b in (*SEGMENTS,(0x14451cccb,0x14451ce4c),(0x14451d0ca,0x14451d0f0)))}
        cs=config.native.capstone.Cs(config.native.capstone.CS_ARCH_X86,config.native.capstone.CS_MODE_64)
        self.allowed.update(i.address for i in cs.disasm(bytes.fromhex(leaf['bytes']),CTOR))
        hooks={0x141421150,0x1487964ac,0x1444aacb0,0x1444e5ff0,0x144522820,0x144522160,0x1444e66b0,
               0x14446eed0,0x1444bbb30,0x14147d580,0x1444baf90,0x1450e50d0,0x14446ea80,0x144469bf0,0x14446fa60,
               0x141420f70,0x1444ab740,0x1444aab90,0x1414313d0,0x1487a2e19}
        pages={a&~4095 for a in self.allowed|hooks}
        pages.update(a&~4095 for f in fragments for r in f['instructions'] for a in r['rip_references'])
        pages.update(a&~4095 for a in GLOBAL_KEYS)
        for address in leaf['rip_references']:pages.add(address&~4095)
        for page in sorted(pages):
            self.uc.mem_map(page,4096)
            try:offset=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[offset:offset+4096])
        self.events,self.values,self.objects,self.body=[],{},{},{}
        self.headers=[];self.method=None
        self.uc.hook_add(ping.unicorn.UC_HOOK_CODE,self.hook)

    def allocate(self,size):
        if not 0<size<=4096 or self.cursor+size>=self.base+0x60000:raise ValueError('SDK JSON fixture allocation bound')
        result=self.cursor;self.cursor+=(size+15)&~15
        return result

    def string(self,desc,text):
        payload=(text+'\0').encode('utf-16le');pointer=self.allocate(len(payload))
        self.uc.mem_write(pointer,payload)
        self.uc.mem_write(desc,struct.pack('<QII',pointer,len(payload)//2,len(payload)//2))

    def wide(self,pointer):
        payload=bytearray()
        for n in range(1024):
            unit=bytes(self.uc.mem_read(pointer+n*2,2))
            if unit==b'\0\0':return payload.decode('utf-16le')
            payload.extend(unit)
        raise ValueError('SDK JSON unterminated wide fixture')

    def text(self,desc):
        pointer,count,capacity=struct.unpack('<QII',bytes(self.uc.mem_read(desc,16)))
        if not count:return ''
        if not 1<=count<=capacity<=1024:raise ValueError('SDK JSON FString bound')
        return self.wide(pointer)

    def variant(self,destination,value):
        pointer=self.allocate(16);self.values[pointer]=value
        self.uc.mem_write(destination,struct.pack('<QQ',pointer,0))

    def pair(self,pointer):
        key_desc,value_desc=struct.unpack('<QQ',bytes(self.uc.mem_read(pointer,16)))
        value_pointer=struct.unpack('<Q',bytes(self.uc.mem_read(value_desc,8)))[0]
        return self.text(key_desc),self.values[value_pointer]

    def hook(self,uc,address,size,user):
        if address in self.allowed:return
        x=self.x
        a,b,c=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        result=0
        if address==0x141421150:
            self.string(a,self.wide(b));result=a
        elif address==0x141420f70:
            payload=bytearray()
            for n in range(128):
                byte=bytes(uc.mem_read(b+n,1))
                if byte==b'\0':break
                payload.extend(byte)
            else:raise ValueError('SDK HTTP narrow literal exceeds bound')
            self.string(a,payload.decode('ascii'));result=a
        elif address==self.base+0x7c000:
            self.headers.append(dict(name=self.text(b),value=self.text(c)))
        elif address==self.base+0x7c010:
            self.method=self.text(b)
        elif address in (0x1444ab740,0x1444aab90):
            result=self.base+(0x2000 if address==0x1444ab740 else 0x8000)
        elif address==0x1414313d0:
            if not 1<=b<=1024:raise ValueError('SDK header allocation bound')
            uc.mem_write(a,struct.pack('<Q',self.allocate(b*2)));uc.mem_write(a+12,struct.pack('<I',b))
        elif address==0x1487a2e19:
            if not 0<c<=2048 or not all(self.base<=p<self.base+0x60000-c for p in (a,b)):
                raise ValueError('SDK header copy outside fixture bounds')
            uc.mem_write(a,bytes(uc.mem_read(b,c)));result=a
        elif address==0x1444aacb0:
            result=self.base+0x2000
            uc.mem_write(result+0x110,struct.pack('<Q',self.base+0x3000))
        elif address in (0x1444e5ff0,0x144522820,0x144522160,0x1444e66b0):
            name={0x1444e5ff0:'nmDeviceKey',0x144522820:'deviceKey',0x144522160:'countryCode',0x1444e66b0:'os'}[address]
            destination=a if address in (0x1444e5ff0,0x1444e66b0) else b
            self.string(destination,self.fixture[name]);result=destination
            self.events.append(dict(kind='getter_return_fixture',name=name,value=self.fixture[name]))
        elif address==0x14446eed0:
            self.variant(a,self.text(b));result=a
        elif address==0x1444bbb30:
            start,end=struct.unpack('<QQ',bytes(uc.mem_read(b,16)))
            if end-start!=64:raise ValueError('SDK body initial pair count differs')
            self.body=dict(self.pair(p) for p in range(start,end,16));result=a
        elif address in (0x1444baf90,0x144469bf0):
            key,value=self.pair(c);self.body[key]=value
            self.events.append(dict(kind='JSON_map_field_capture',name=key,value=value));result=b
        elif address==0x1450e50d0:
            pointer=self.allocate(16);self.objects[pointer]=dict(self.fixture['credential'])
            uc.mem_write(b,struct.pack('<QQ',pointer,0));result=b
            self.events.append(dict(kind='credential_GetObject_return_fixture',value=dict(self.fixture['credential'])))
        elif address==0x14446ea80:
            pointer=struct.unpack('<Q',bytes(uc.mem_read(b,8)))[0]
            self.variant(a,self.objects[pointer]);result=a
        elif address not in (0x1487964ac,0x14147d580,0x14446fa60):
            raise ValueError('Unreviewed SDK body target '+hex(address))
        rsp=uc.reg_read(x.UC_X86_REG_RSP);ret=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RAX,result);uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,ret)

    def function(self,address,**regs):
        self.uc.mem_write(self.stack,struct.pack('<Q',self.stop));self.uc.reg_write(self.x.UC_X86_REG_RSP,self.stack)
        for name,value in regs.items():self.uc.reg_write(getattr(self.x,'UC_X86_REG_'+name.upper()),value)
        self.uc.emu_start(address,self.stop,count=8192)
        if self.uc.reg_read(self.x.UC_X86_REG_RIP)!=self.stop:raise ValueError('SDK initialization budget exceeded')

    def capture(self,fixture):
        self.fixture=fixture
        for rva in sorted(self.initializers):self.function(rva+0x140000000)
        auth=self.base+0x4000
        self.function(CTOR,rcx=auth)
        key_pointer=struct.unpack('<Q',bytes(self.uc.mem_read(auth+0x30,8)))[0]
        optional_key=self.wide(key_pointer)
        player=self.base+0x5000;pair=self.base+0x5100;credential=self.base+0x5200;table=self.base+0x5300
        self.string(player,fixture['playerId'])
        self.uc.mem_write(pair,struct.pack('<QQ',credential if fixture['credential'] else 0,0))
        self.uc.mem_write(credential,struct.pack('<Q',table));self.uc.mem_write(table+8,struct.pack('<Q',0x1450e50d0))
        for n,(start,end) in enumerate(SEGMENTS):
            regs=dict(rsp=self.stack,rbp=self.rbp,r15=auth,r14=0,rsi=player,r12=pair,rbx=0xffffffff)
            for name,value in regs.items():self.uc.reg_write(getattr(self.x,'UC_X86_REG_'+name.upper()),value)
            try:self.uc.emu_start(start,end,count=8192)
            except Exception as error:
                raise ValueError('SDK body segment '+str(n)+' failed at '+hex(self.uc.reg_read(self.x.UC_X86_REG_RIP))) from error
            if self.uc.reg_read(self.x.UC_X86_REG_RIP)!=end:raise ValueError('SDK body slice instruction budget exceeded')
        return dict(fixture=fixture,body=self.body,optional_key=optional_key,events=self.events,network_ready=False)

    def capture_headers(self,code,account_value):
        for rva in sorted(self.initializers):self.function(rva+0x140000000)
        settings=self.base+0x3000;account=self.base+0x9000
        self.uc.mem_write(self.base+0x2000+0x110,struct.pack('<Q',settings))
        self.uc.mem_write(self.base+0x8000+0x110,struct.pack('<Q',account))
        self.string(settings+0x38,'thered');self.uc.mem_write(settings+0x48,bytes([code]))
        self.string(account+0x78,account_value)
        pair,request,table=self.base+0x7000,self.base+0x7100,self.base+0x7200
        self.uc.mem_write(pair,struct.pack('<Q',request));self.uc.mem_write(request,struct.pack('<Q',table))
        self.uc.mem_write(table+0xb0,struct.pack('<Q',self.base+0x7c000))
        self.uc.mem_write(table+0x60,struct.pack('<Q',self.base+0x7c010))
        for name,value in dict(rsp=self.stack,rbp=self.rbp,r13=pair,rsi=0).items():
            self.uc.reg_write(getattr(self.x,'UC_X86_REG_'+name.upper()),value)
        for start,end in ((0x14451cccb,0x14451ce4c),(0x14451d0ca,0x14451d0f0)):
            self.uc.emu_start(start,end,count=8192)
            if self.uc.reg_read(self.x.UC_X86_REG_RIP)!=end:raise ValueError('SDK header slice budget exceeded')
        return dict(build_byte=code,account_field_78=account_value,headers=self.headers,method=self.method)


def build():
    prior=json.loads((config.native.ROOT/'code-clues/headless-auth-index.json').read_text('utf-8'))
    raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('SDK sign-in EXE changed')
    image=config.native.Image(raw)
    network=config.native.decode_ranges(image,{image.roots[image.containing(0x14451c600)]})
    header_keys={a for f in network for r in f['instructions'] if 0x14451cccb<=r['address']<0x14451ce4c
                 and r['mnemonic']=='lea' for a in r['rip_references'] if a>=0x14b000000}
    candidates=config.native.rip_candidates(image,set(GLOBAL_KEYS)|header_keys)
    initializers={image.roots[image.containing(a)] for a,t in candidates if image.containing(a)
                  and image.roots[image.containing(a)][0]<0x2000000}
    init_rvas={r[0] for r in initializers}
    if len(init_rvas)!=11:raise ValueError('SDK body/header key initializer coverage changed')
    initializers.update(image.roots[image.containing(a)] for a in bootstrap.INITIALIZERS)
    init_rvas={r[0] for r in initializers}
    addresses=(0x1444fb800,0x144510fd0,0x1444bc1d0,0x1445209e0,0x1444fb730,
               0x1444e5ff0,0x144522820,0x144522160,0x1444e66b0,0x14451c3f0,0x14451c600,bootstrap.BUILD)
    fragments=config.native.decode_ranges(image,initializers|{image.roots[image.containing(a)] for a in addresses})
    cs=config.native.capstone.Cs(config.native.capstone.CS_ARCH_X86,config.native.capstone.CS_MODE_64);cs.detail=True
    offset=image.offset(CTOR-image.pe.base);instructions=[]
    for i in cs.disasm(raw[offset:offset+512],CTOR):
        instructions.append(i)
        if i.mnemonic=='ret':break
    if not instructions or instructions[-1].mnemonic!='ret' or any(i.mnemonic in ('call','jmp') for i in instructions):
        raise ValueError('Auth constructor leaf changed')
    content=raw[offset:offset+sum(i.size for i in instructions)]
    refs=[i.address+i.size+op.mem.disp for i in instructions for op in i.operands
          if op.type==config.native.capstone.x86_const.X86_OP_MEM and op.mem.base==config.native.capstone.x86_const.X86_REG_RIP]
    leaf=dict(address=CTOR,file_offset=offset,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest(),rip_references=refs)
    literals=[]
    for f in fragments:
        for row in f['instructions']:
            if row['mnemonic']=='lea':
                for a in row['rip_references']:
                    literal=config.read_literal(raw,image,a)
                    if literal and (f['root_begin_rva'] in init_rvas or literal['text'] in ('authUrl','v1/sign-in')):
                        literals.append(dict(instruction=row['address'],**literal))
    cases=[]
    for player in ('','player-fixture'):
        for credential in (None,dict(channelCode=33,channelAccessToken='provider-token-fixture')):
            fixture=dict(nmDeviceKey='nm-fixture',deviceKey='device-fixture',countryCode='UA',os='pc',
                         playerId=player,credential=credential)
            cases.append(Replay(raw,image,fragments,leaf,init_rvas).capture(fixture))
    headers=[Replay(raw,image,fragments,leaf,init_rvas).capture_headers(code,value)
             for code in (0,1,2,255) for value in ('','account-fixture')]
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),fragments=fragments,constructor_leaf=leaf,
        literals=literals,constructor_literals=[v for a in refs if (v:=config.read_literal(raw,image,a))],
        cases=cases,headers=headers,network_ready=False,limitations=[
            'Native sign-in body preparation/conditional branches and auth constructor leaf executed.',
            'Device/settings getters, credential GetObject, JSON values/map and allocations/free/atexit are fixtures/captures.',
            'Native CreatePost default header/method slices and build getter executed; request vtable calls captured, settings/module identity fixture.',
            'Custom headers/body serialization, actual HTTP and SDK response not executed; factory/getter/wrapper source chain is static.',
            'Optional playerId key comes from constructed auth+0x30; active account/config not read; SDK response/session pending.'])


if __name__=='__main__':
    report=build();path=config.native.ROOT/'code-clues/sdk-sign-in-body-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases'])),indent=2))
