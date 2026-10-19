"""Bounded title auth-success slices and actual BeginGame IsSignIn gate; UI middle excluded."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('title_state_source',HERE/'replay-sdk-result-dispatch.py')
dispatch=importlib.util.module_from_spec(spec);spec.loader.exec_module(dispatch)
native,x=dispatch.native,dispatch.x
TITLE,HEAD_END,FLAG_BEGIN=0x14641d560,0x14641d70a,0x14641dac5
GATE,PASS,FAIL=0x14641809c,0x1464181bc,0x1464180a9


class Replay(dispatch.Replay):
    def __init__(self,raw,image,fragments,fixture):
        super().__init__(raw,image,fragments,dict(bound=False,refcounted=False,execute_ok=False))
        self.fixture=fixture
        rows=[]
        for f in fragments:
            for r in f['instructions']:
                a=r['address']
                if (f['root_begin_rva']==0x641d560 and (TITLE<=a<HEAD_END or FLAG_BEGIN<=a<=0x14641dbbf)) or f['root_begin_rva'] in (0x5609b00,0x452afb0):
                    rows.append(r)
                elif GATE<=a<FAIL:rows.append(r)
        self.allowed={r['address'] for r in rows}
        self.targets={0x1456048a0,0x14142d840,0x141424430,0x14147d580,0x145564550,0x1456041d0,
                      0x14556d5f0,0x145c859f0,0x145c82600,0x14563d980,0x1456048f0,0x145636eb0,
                      0x1444aacb0}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in (*self.targets,HEAD_END,PASS,FAIL))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.title=self.allocate(0x1000);self.interface=self.title+0xa18
        self.manager,self.auth_service,self.generic,self.settings_class,self.settings=(self.allocate(n) for n in (0x120,0x100,0x100,0x120,0x500))
        self.uc.mem_write(self.manager+0x38,struct.pack('<Q',self.auth_service if fixture['auth_service'] else 0))
        self.uc.mem_write(self.settings_class+0x110,struct.pack('<Q',self.settings))
        self.uc.mem_write(self.settings+0x400,bytes([fixture['sdk_flag']]))
        self.events=[]
        # Explicit debug/dialog flag off; this is not an active application setting.
        self.uc.mem_write(0x14b520cc4,b'\0')

    def string(self,descriptor,value):
        data=(value+'\0').encode('utf-16le');ptr=self.allocate(len(data))
        self.uc.mem_write(ptr,data);self.uc.mem_write(descriptor,struct.pack('<QII',ptr,len(data)//2,len(data)//2))

    def text(self,descriptor):
        ptr,count,cap=struct.unpack('<QII',bytes(self.uc.mem_read(descriptor,16)))
        if not count:return ''
        if not 1<=count<=cap<=256:raise ValueError('Title text fixture bound')
        return bytes(self.uc.mem_read(ptr,count*2)).decode('utf-16le')[:-1]

    def hook(self,uc,address,size,user):
        if address in (HEAD_END,PASS,FAIL):uc.emu_stop();return
        if address in self.allowed:return
        a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
        result=0
        if address==0x1456048a0:result=self.manager if self.fixture['manager'] else 0
        elif address==0x14142d840:
            self.uc.mem_write(a,b'\0'*16);result=a
        elif address in (0x141424430,0x14147d580):pass
        elif address in (0x145564550,0x145c859f0,0x14563d980):result=self.generic
        elif address==0x1456041d0:
            self.string(b,self.fixture['country']);result=b
            self.events.append(dict(action='sdk_country_getter_fixture',value=self.fixture['country']))
        elif address==0x14556d5f0:
            self.events.append(dict(action='connect_country_setter_capture',value=self.text(b)))
        elif address==0x145c82600:result=0
        elif address==0x1456048f0:
            self.string(b,'player-fixture');result=b
        elif address==0x145636eb0:
            self.events.append(dict(action='title_post_action_capture',target=address))
        elif address==0x1444aacb0:result=self.settings_class
        else:raise ValueError('Unexpected title auth-state execution '+hex(address))
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        self.uc.mem_write(self.stack,struct.pack('<Q',self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP,self.stack);self.uc.reg_write(x.UC_X86_REG_RCX,self.interface)
        self.uc.emu_start(TITLE,self.stop,count=2048)
        reached=self.uc.reg_read(x.UC_X86_REG_RIP)==HEAD_END
        head_rip=self.uc.reg_read(x.UC_X86_REG_RIP)
        if head_rip not in (HEAD_END,self.stop):raise ValueError('Title head budget')
        if reached:
            # Research slice, not a claim that all excluded UI/country blacklist branches pass.
            self.events.append(dict(action='fixture_skip_title_middle',begin=HEAD_END,end=FLAG_BEGIN))
            self.uc.emu_start(FLAG_BEGIN,self.stop,count=2048)
            if self.uc.reg_read(x.UC_X86_REG_RIP)!=self.stop:raise ValueError('Title tail budget')
        flag=int.from_bytes(self.uc.mem_read(self.interface+0x230,1),'little')
        self.uc.mem_write(self.stack,struct.pack('<Q',self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP,self.stack)
        self.uc.reg_write(x.UC_X86_REG_RCX,self.auth_service)
        self.uc.emu_start(GATE,self.stop,count=1024)
        gate=self.uc.reg_read(x.UC_X86_REG_RIP)
        if gate not in (PASS,FAIL):raise ValueError('BeginGame gate budget')
        return dict(fixture=self.fixture,title_head_reached=reached,title_ready_byte=flag,
                    sdk_flag_after=int.from_bytes(self.uc.mem_read(self.settings+0x400,1),'little'),
                    begin_game_gate_passed=gate==PASS,events=self.events)


def build():
    entry_path=native.ROOT/'code-clues/entry-code.json'
    prior=json.loads(entry_path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Title state source changed')
    image=native.Image(raw)
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in (dispatch.DISPATCH,TITLE,0x146417ad0,0x145609b00,0x14452afb0,0x1456041d0,0x14556d5f0)})
    literals=[]
    for f in fragments:
        for row in f['instructions']:
            for ref in row['rip_references']:
                if lit:=dispatch.completion.gates.fields.lifecycle.guid.source.config.read_literal(raw,image,ref):
                    literals.append(dict(instruction=row['address'],**lit))
    base=dict(manager=True,auth_service=True,country='UA',sdk_flag=False)
    profiles=[]
    for sdk_flag in (False,True):
        for country in ('','UA','KR'):
            profiles.append(dict(base,name=f'country-{country}-flag-{sdk_flag}',country=country,sdk_flag=sdk_flag))
        profiles.append(dict(base,name=f'no-manager-{sdk_flag}',manager=False,sdk_flag=sdk_flag))
        profiles.append(dict(base,name=f'no-auth-service-{sdk_flag}',auth_service=False,sdk_flag=sdk_flag))
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                entry_report_sha256=hashlib.sha256(entry_path.read_bytes()).hexdigest(),fragments=fragments,literals=literals,
                cases=[Replay(raw,image,fragments,f).capture() for f in profiles],native_execution=True,network_ready=False,
                limitations=[
                    'Native title auth-success head and tail execute as separate slices; UI/country blacklist middle deliberately skipped.',
                    'Country getter/ConnectCountryCode setter, formatting, player getter and post actions are fixtures/captures.',
                    'Actual BeginGame call/test/branch plus game IsSignIn wrapper and settings getter execute.',
                    'Settings CDO/context and flags are independent fixtures; no real origin/token/expiry/account validation.',
                    'Passed gate stops before BeginGameImpl; no game Login packet, UI activation or network executed.',
                    'No game launch/process memory/profile/credentials/HTTP used.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/title-auth-state-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
