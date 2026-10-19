"""Native sockaddr/connect/result wrapper over explicit Winsock and readiness fixtures."""
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('connect_socket_source',HERE/'replay-resolved-socket-setup.py')
source=importlib.util.module_from_spec(spec);spec.loader.exec_module(source)
native,x=source.native,source.x
WRAPPER,LOWER=0x1445e5c60,0x1445ecbb0
HOOKS={0x148945a30:0x30000200,0x148945a40:0x30000210,0x148945af8:0x30000220,0x148945aa0:0x30000230}
OPTION,MODE,ERROR=0x30000240,0x30000250,0x30000260


class Replay(source.resolver.handoff.connect.begin.dispatch.Replay):
    def __init__(self,raw,image,fragments,fixture):
        super().__init__(raw,image,fragments,dict(bound=False,refcounted=False,execute_ok=False))
        self.fixture=fixture
        rows=[r for f in fragments if f['root_begin_rva']+image.pe.base in (WRAPPER,LOWER) for r in f['instructions']]
        self.allowed={r['address'] for r in rows}
        self.targets={*HOOKS.values(),OPTION,MODE,ERROR,0x141e0e6a0,0x1445ea840,0x14142c480,0x148796040}
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in self.targets)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        for iat,hook in HOOKS.items():self.uc.mem_write(iat,struct.pack('<Q',hook))
        self.socket,self.endpoint,self.engine,self.engine_table=(self.allocate(n) for n in (0x70,0x40,16,0x80))
        self.uc.mem_write(self.socket+0x38,struct.pack('<I',fixture['handle']))
        self.uc.mem_write(self.socket+0x3c,bytes([fixture['mode_byte']]))
        self.std_write(self.endpoint+8,fixture['host'].encode('ascii'))
        self.uc.mem_write(self.endpoint+0x28,struct.pack('<H',fixture['port']))
        self.uc.mem_write(self.endpoint+0x2c,struct.pack('<I',fixture['family_tag']))
        self.uc.mem_write(self.engine,struct.pack('<Q',self.engine_table))
        for slot,target in ((0x58,OPTION),(0x30,MODE),(0x68,ERROR)):
            self.uc.mem_write(self.engine_table+slot,struct.pack('<Q',target))
        self.uc.mem_write(0x14b4f39d0,struct.pack('<Q',self.engine))
        self.events=[];self.mode_calls=0;self.lower_result=None

    def std_write(self,desc,data):
        if len(data)<=15:
            self.uc.mem_write(desc,data+b'\0'*(16-len(data)))
            self.uc.mem_write(desc+16,struct.pack('<QQ',len(data),15))
        else:
            ptr=self.allocate(len(data)+1);self.uc.mem_write(ptr,data+b'\0')
            self.uc.mem_write(desc,struct.pack('<QQQQ',ptr,0,len(data),len(data)))

    def ctext(self,ptr):
        data=bytearray()
        for n in range(256):
            c=bytes(self.uc.mem_read(ptr+n,1))
            if c==b'\0':return data.decode('ascii')
            data.extend(c)
        raise ValueError('Sockaddr fixture string bound')

    def hook(self,uc,address,size,user):
        if address==0x1445e5c6e:self.lower_result=uc.reg_read(x.UC_X86_REG_RAX)&255
        if address in self.allowed:return
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==HOOKS[0x148945a30]:
            result=int.from_bytes(struct.pack('>H',a&65535),'little')
        elif address==HOOKS[0x148945a40]:
            host=self.ctext(a);packed=ipaddress.IPv4Address(host).packed
            result=int.from_bytes(packed,'little')
            self.events.append(dict(action='inet_addr_fixture',host=host))
        elif address==HOOKS[0x148945af8]:
            host=self.ctext(b);packed=ipaddress.IPv6Address(host).packed
            if a!=23:raise ValueError('IPv6 conversion family changed')
            uc.mem_write(c,packed);result=1
            self.events.append(dict(action='inet_pton_fixture',family=a,host=host))
        elif address==HOOKS[0x148945aa0]:
            if c not in (16,28):raise ValueError('Sockaddr size changed')
            data=bytes(uc.mem_read(b,c));family=int.from_bytes(data[:2],'little');port=int.from_bytes(data[2:4],'big')
            host=str(ipaddress.ip_address(data[4:8] if family==2 else data[8:24]))
            self.events.append(dict(action='winsock_connect_fixture',handle=a,family=family,port=port,host=host,
                                    sockaddr_size=c,sockaddr_hex=data.hex(),returned=self.fixture['connect_return']))
            result=self.fixture['connect_return']&0xffffffffffffffff
        elif address==OPTION:
            desc=int.from_bytes(uc.mem_read(uc.reg_read(x.UC_X86_REG_RSP)+0x28,8),'little')
            self.events.append(dict(action='option_get_capture',selector=d,initial=int.from_bytes(uc.mem_read(desc+8,4),'little')))
        elif address==MODE:
            requested=int.from_bytes(uc.mem_read(d,8),'little')
            ok=self.fixture['mode_results'][min(self.mode_calls,len(self.fixture['mode_results'])-1)]
            self.mode_calls+=1;result=int(ok)
            self.events.append(dict(action='mode_engine_capture',requested=requested,returned=result))
        elif address==ERROR:
            result=self.fixture['engine_error'];self.events.append(dict(action='engine_error_capture',value=result))
        elif address==0x141e0e6a0:
            # One raw socket pointer, vector storage fixture only.
            ptr=self.allocate(8);uc.mem_write(ptr,bytes(uc.mem_read(c,8)))
            uc.mem_write(a,struct.pack('<QQQ',ptr,ptr+8,ptr+8));result=a
        elif address==0x1445ea840:
            if a!=0 or c!=0:raise ValueError('Wait helper arguments changed')
            if not self.fixture['ready_nonempty']:
                ptr=int.from_bytes(uc.mem_read(b,8),'little');uc.mem_write(b+8,struct.pack('<Q',ptr))
            result=int(self.fixture['wait_ok'])
            self.events.append(dict(action='wait_helper_capture',timeout=d,returned=result,nonempty=self.fixture['ready_nonempty']))
        elif address==0x14142c480:pass
        elif address==0x148796040:result=uc.reg_read(x.UC_X86_REG_RAX)
        else:raise ValueError('Unexpected native connect instruction '+hex(address))
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def capture(self):
        self.run(WRAPPER,self.socket,self.endpoint)
        return dict(fixture=self.fixture,lower_result=self.lower_result,wrapper_result=self.uc.reg_read(x.UC_X86_REG_RAX)&255,
                    socket_state_50=int.from_bytes(self.uc.mem_read(self.socket+0x50,4),'little'),
                    socket_timeout_58=int.from_bytes(self.uc.mem_read(self.socket+0x58,4),'little'),events=self.events)


def export_name(raw,image,info):
    pe=struct.unpack_from('<I',raw,60)[0];rva,size=struct.unpack_from('<II',raw,pe+24+112);off=image.offset(rva)
    base,count,names,functions,nt,ot=struct.unpack_from('<IIIIII',raw,off+16)
    index=info['ordinal']-base
    if not 0<=index<count:raise ValueError('Connect ordinal outside DLL exports')
    for n in range(names):
        op=image.offset(ot)+n*2
        if struct.unpack_from('<H',raw,op)[0]!=index:continue
        nrva=struct.unpack_from('<I',raw,image.offset(nt)+n*4)[0];pos=image.offset(nrva);end=raw.index(b'\0',pos)
        return dict(name=raw[pos:end].decode('ascii'),name_offset=pos,name_bytes=raw[pos:end+1].hex(),
                    ordinal_index_offset=op,ordinal_index_bytes=raw[op:op+2].hex())
    raise ValueError('Connect ordinal name missing')


def build():
    path=native.ROOT/'code-clues/resolved-socket-setup-replay.json'
    prior=json.loads(path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Connect result source changed')
    image=native.Image(raw);fragments=prior['fragments']
    spec=importlib.util.spec_from_file_location('result_imports',HERE/'build-headless-send-drain.py')
    imports=importlib.util.module_from_spec(spec);spec.loader.exec_module(imports)
    spec=importlib.util.spec_from_file_location('result_named_imports',HERE/'build-object-zero-init-code.py')
    named=importlib.util.module_from_spec(spec);spec.loader.exec_module(named)
    dll=Path(imports.os.environ['SystemRoot'])/'System32/WS2_32.dll';dllraw=dll.read_bytes();dllimage=native.Image(dllraw)
    evidence=[]
    for iat,expected in ((0x148945a30,'htons'),(0x148945a40,'inet_addr'),(0x148945aa0,'connect')):
        info=imports.ordinal_import(raw,image,iat);exp=export_name(dllraw,dllimage,info)
        if info['dll'].lower()!='ws2_32.dll' or exp['name']!=expected:raise ValueError('Connect import/export mismatch')
        evidence.append(dict(import_info=info,export=exp))
    pton=named.import_at(raw,image,0x148945af8)
    if pton['name'].lower()!='inet_pton':raise ValueError('IPv6 parser import changed')
    base=dict(handle=42,host='192.0.2.1',port=12345,family_tag=0,mode_byte=0,connect_return=0,
              engine_error=0,mode_results=[True,True],wait_ok=True,ready_nonempty=True)
    fixtures=[dict(base,name='ipv4-immediate'),dict(base,name='ipv6-immediate',host='2001:db8::1',family_tag=1),
              dict(base,name='zero-handle',handle=0)]
    for error in (0,21,22,23,24,36,37,38):
        fixtures.append(dict(base,name='connect-fail-engine-'+str(error),connect_return=-1,engine_error=error))
    for name,change in [('wait-ready',{}),('wait-false',dict(wait_ok=False)),('wait-empty',dict(ready_nonempty=False)),
                        ('mode-enter-fail',dict(mode_results=[False])),('mode-restore-fail',dict(mode_results=[True,False]))]:
        fixtures.append(dict(base,name=name,mode_byte=1,connect_return=-1,**change))
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fragments=fragments,imports=evidence,ipv6_import=pton,
        winsock_dll=dict(path=str(dll),sha256=hashlib.sha256(dllraw).hexdigest()),
        cases=[Replay(raw,image,fragments,f).capture() for f in fixtures],native_execution=True,network_ready=False,
        limitations=[
            'Actual endpoint-connect wrapper and lower sockaddr/connect/result bodies execute, isolated from earlier setup.',
            'Winsock htons/inet_addr/inet_pton/connect are fixtures; exact system call args and sockaddr bytes captured, no real sockets.',
            'Engine error getter returns raw internal numbers; no unproven WSA error-name mapping.',
            'Mode/wait/vector/options helpers are fixtures; successful wait does not model SO_ERROR or real readiness.',
            'Wrapper acceptance of errors22/23/37 is internal continuation acceptance, not connected/authenticated session.',
            'No active account/profile/process memory/game launch/network/Android parity or packet Login proof.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/socket-connect-result-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
