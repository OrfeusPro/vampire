"""Native OnResult save/credential continuation and GetObject; storage/JSON/map captures."""
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nid_credential_primitives', HERE / 'replay-nid-result-primitives.py')
primitives = importlib.util.module_from_spec(spec)
spec.loader.exec_module(primitives)
config = primitives.config
STOP = 0x1450ef51f
FUNCTIONS = (0x144521550, 0x1444bd500, 0x1444f8fd0, 0x1444f9050, 0x1450e50d0, 0x1444e6570)
VTABLE = 0x1496e16f0


class Replay(primitives.Replay):
    def __init__(self, raw, image, fragments, bindings, evidence, crt, extra, save_result):
        super().__init__(raw, image, fragments, bindings, evidence, crt)
        self.save_result = save_result
        self.registered = []
        self.json_fields = {}
        self.return_objects = {}
        rows = [r for f in extra for r in f['instructions']]
        additions = {r['address'] for r in rows if f_root(extra, r['address']) != 0x50ee6b0
                     or primitives.validation.END <= r['address'] <= STOP}
        pages = {a & ~4095 for a in additions | {0x14453cdf0,0x1444f5190,0x1468e4100,
            0x14446e420,0x1444bb100,0x141420f70,0x1444822f0,0x144482210}}
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        regions = list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in regions):
                continue
            self.uc.mem_map(page,4096)
            try:
                offset=image.offset(page-image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page,raw[offset:offset+4096])
        self.allowed.update(additions)
        self.uc.mem_write(0x14b4f2060,b'\0')  # Explicit diagnostic logging-disabled fixture.
        self.service_handle,self.service,self.manager_impl=self.base+0x9000,self.base+0xa000,self.base+0xb000
        self.uc.mem_write(self.service_handle,struct.pack('<Q',self.service))
        self.uc.mem_write(self.service+0x170,struct.pack('<Q',self.manager_impl))
        self.uc.mem_write(self.rbp-0x78,struct.pack('<Q',self.service_handle))

    def hook(self,uc,address,size,user):
        if address==STOP:
            self.outcome='credential_registration_reached'
            uc.emu_stop()
            return
        if address==primitives.validation.END:
            return  # Execute the previously terminal Save call, then continue.
        special={0x14453cdf0,0x1444f5190,0x1468e4100,0x14446e420,0x1444bb100,
                 0x141420f70,0x1444822f0,0x144482210}
        if address not in special:
            return super().hook(uc,address,size,user)
        x=self.x
        a,b,c=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        result=0
        if address==0x14453cdf0:
            self.events.append(dict(kind='Save_return_fixture',value=self.save_result))
            result=int(self.save_result)
        elif address==0x1444f5190:
            self.events.append(dict(kind='RemoveAllCredentials_capture',receiver=a))
        elif address==0x1468e4100:
            result=self.allocate(a)
            uc.mem_write(result,b'\0'*a)
        elif address==0x14446e420:
            uc.mem_write(a,b'\0'*0x48)
            uc.mem_write(a,struct.pack('<Q',self.allocate(64)))
            self.json_fields[a]={}
            result=a
        elif address==0x141420f70:
            payload=bytearray()
            for n in range(256):
                byte=bytes(uc.mem_read(b+n,1))
                if byte==b'\0':
                    break
                payload.extend(byte)
            else:
                raise ValueError('Narrow literal exceeds fixture bound')
            self.string(a,payload.decode('ascii','strict'))
            result=a
        elif address==0x1444bb100:
            key_pointer,pair_pointer=struct.unpack('<QQ',bytes(uc.mem_read(c,16)))
            key=bytes(uc.mem_read(key_pointer,1))[0]
            credential,control=struct.unpack('<QQ',bytes(uc.mem_read(pair_pointer,16)))
            code=bytes(uc.mem_read(credential+0x50,1))[0]
            table=struct.unpack('<Q',bytes(uc.mem_read(credential,8)))[0]
            if a!=self.manager_impl+0x20 or key!=code or table!=VTABLE or not control:
                raise ValueError('Unexpected native credential insertion arguments')
            # Explicit retained-reference behavior for the captured map insertion.
            count=struct.unpack('<I',bytes(uc.mem_read(control+8,4)))[0]
            uc.mem_write(control+8,struct.pack('<I',count+1))
            row=dict(kind='credential_map_insert_capture',channel=key,credential=credential,
                     access_token=self.text(credential+0x58),vtable=table,retained_reference_shim=True)
            self.registered.append(row)
            self.events.append(row)
        elif address in (0x1444822f0,0x144482210):
            if a not in self.json_fields:
                raise ValueError('Unexpected JSON receiver')
            name=self.text(b)
            value=self.text(c) if address==0x1444822f0 else c
            self.json_fields[a][name]=value
            self.events.append(dict(kind='JSON_field_capture',name=name,value=value))
        rsp=uc.reg_read(x.UC_X86_REG_RSP)
        ret=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RAX,result)
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8)
        uc.reg_write(x.UC_X86_REG_RIP,ret)

    def capture(self,fields):
        result=self.run(fields)
        # Real integer/channel code was executed, so inherited fixture labels do not apply.
        for name in ('parse_ok','parsed_value','channel'):
            result.pop(name)
        if len(self.registered)!=1:
            raise ValueError('Expected one credential insertion capture')
        obj=self.registered[0]['credential']
        self.events=[]
        self.function(0x1450e50d0,rcx=obj,rdx=self.base+0xd000)
        result.update(save_result=self.save_result,provider_channel=20,
            sdk_channel=self.registered[0]['channel'],payload=dict(self.json_fields[obj+8]),
            serialization_events=list(self.events),native_setters_or_storage_executed=False)
        return result


def f_root(fragments,address):
    for f in fragments:
        if 0x140000000+f['begin_rva']<=address<0x140000000+f['end_rva']:
            return f['root_begin_rva']
    raise ValueError('Continuation instruction outside source fragments')


def build():
    prior=json.loads((config.native.ROOT/'code-clues/headless-nid-result.json').read_text('utf-8'))
    primitive_path=config.native.ROOT/'code-clues/nid-result-primitives.json'
    primitive=json.loads(primitive_path.read_text('utf-8'))
    raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:
        raise ValueError('Credential source EXE changed')
    image=config.native.Image(raw)
    evidence=primitives.sources(raw,image)
    if evidence!=primitive['evidence']:
        raise ValueError('Upstream native primitive evidence differs')
    crt_path=Path(primitive['crt']['path'])
    if hashlib.sha256(crt_path.read_bytes()).hexdigest()!=primitive['crt']['sha256']:
        raise ValueError('Pinned local CRT changed')
    crt=ctypes.CDLL(str(crt_path))
    crt._wtoi.argtypes,crt._wtoi.restype=[ctypes.c_wchar_p],ctypes.c_int
    crt._finite.argtypes,crt._finite.restype=[ctypes.c_double],ctypes.c_int
    crt.iswspace.argtypes,crt.iswspace.restype=[ctypes.c_ushort],ctypes.c_int
    fragments=config.native.decode_ranges(image,{image.roots[image.containing(a)] for a in (primitives.validation.START,0x141420cc0)})
    extra=config.native.decode_ranges(image,{image.roots[image.containing(a)] for a in (primitives.validation.START,*FUNCTIONS)})
    static=config.native.decode_ranges(image,{image.roots[image.containing(a)] for a in (0x14453cdf0,0x1444f5190)})
    literals=[]
    for fragment in extra:
        for row in fragment['instructions']:
            if row['mnemonic']=='lea':
                for address in row['rip_references']:
                    literal=config.read_literal(raw,image,address)
                    if literal and literal['text'] in ('channelCode','channelAccessToken'):
                        literals.append(dict(instruction=row['address'],**literal))
    offset=image.offset(VTABLE-image.pe.base)
    table=raw[offset:offset+16]
    if struct.unpack_from('<Q',table,8)[0]!=0x1450e50d0:
        raise ValueError('Credential GetObject vtable slot changed')
    fields=dict(resultCode='0',accessToken='access-fixture',refreshToken='refresh-fixture',channelKey='mailUserKey',
                netmarbleId='user-fixture',joinedCountryCode='UA')
    cases=[]
    for saved in (False,True):
        for token in ('access-fixture','token+fixture='):
            vm=Replay(raw,image,fragments,prior['bindings'],evidence,crt,extra,saved)
            cases.append(vm.capture({**fields,'accessToken':token}))
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        primitive_report_sha256=hashlib.sha256(primitive_path.read_bytes()).hexdigest(),
        fragments=extra,static_fragments=static,literals=literals,
        vtable=dict(address=VTABLE,file_offset=offset,bytes=table.hex(),sha256=hashlib.sha256(table).hexdigest()),
        cases=cases,network_ready=False,limitations=[
            'Native OnResult continuation/base credential constructor/manager getter/wrapper/SetCredential/GetObject executed.',
            'Storage Save return, clear credentials, JSON initializer/fields and final map insertion are explicit captures/shims.',
            'Map insertion retain count is a shim; allocation/copy/free/atexit and earlier map dependencies remain bounded fixtures.',
            'Provider channel 20 differs from credential channelCode 33; no SDK sign-in, server response, game session or persistence.'])


if __name__=='__main__':
    report=build()
    path=config.native.ROOT/'code-clues/nid-credential-adoption-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases'])),indent=2))
