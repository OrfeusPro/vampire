"""Native WSAGetLastError switch through engine vtable into actual connect wrapper."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('wsa_connect_source',HERE/'replay-socket-connect-result.py')
connect=importlib.util.module_from_spec(spec);spec.loader.exec_module(connect)
native,x=connect.native,connect.x
MAP,TABLE,JUMPS,WSA_HOOK=0x1445f0680,0x149504668,0x1445f0828,0x30000270


class Replay(connect.Replay):
    def __init__(self,raw,image,fragments,code,fixture):
        super().__init__(raw,image,fragments,fixture)
        self.allowed.update(r['address'] for r in code['instructions'])
        pages={a & ~4095 for r in code['instructions'] for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in (WSA_HOOK,TABLE,JUMPS))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.uc.mem_write(0x148945ad0,struct.pack('<Q',WSA_HOOK))
        # Other engine slots remain inherited fixtures; error slot uses actual source target.
        self.uc.mem_write(self.engine_table+0x68,struct.pack('<Q',MAP))
        self.mapped_result=None

    def hook(self,uc,address,size,user):
        if address==0x1445e5c85:
            self.mapped_result=uc.reg_read(x.UC_X86_REG_RAX)&0xffffffff
            self.events.append(dict(action='native_mapped_error_return',value=self.mapped_result))
        if address in self.allowed:return super().hook(uc,address,size,user)
        if address==WSA_HOOK:
            result=self.fixture['wsa_error']
            self.events.append(dict(action='WSAGetLastError_fixture',value=result))
            uc.reg_write(x.UC_X86_REG_RAX,result&0xffffffff)
            rsp=uc.reg_read(x.UC_X86_REG_RSP);target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
            uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)
            return
        return super().hook(uc,address,size,user)

    def capture(self):
        result=super().capture();result['mapped_error']=self.mapped_result
        return result


def build():
    path=native.ROOT/'code-clues/socket-connect-result-replay.json'
    prior=json.loads(path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('WSA mapping source changed')
    image=native.Image(raw)
    # Exception range includes switch data: decode only code, export table separately.
    off=image.offset(MAP-image.pe.base);content=raw[off:off+0x1a6]
    cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
    rows=[]
    for i in cs.disasm(content,MAP):
        refs=[i.address+i.size+op.mem.disp for op in i.operands if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
        rows.append(dict(address=i.address,file_offset=off+i.address-MAP,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=refs))
    if sum(len(bytes.fromhex(r['bytes'])) for r in rows)!=len(content) or rows[-1]['address']!=0x1445f0825:
        raise ValueError('WSA mapping code boundary changed')
    code=dict(address=MAP,file_offset=off,bytes=content.hex(),sha256=hashlib.sha256(content).hexdigest(),instructions=rows)
    toff=image.offset(JUMPS-image.pe.base);table=raw[toff:toff+37*4]
    targets=[image.pe.base+v for v in struct.unpack('<'+'I'*37,table)]
    if any(t not in {r['address'] for r in rows} for t in targets):raise ValueError('WSA switch target not a code boundary')
    voff=image.offset(TABLE-image.pe.base);vbytes=raw[voff:voff+0x70]
    if struct.unpack_from('<Q',vbytes,0x68)[0]!=MAP:raise ValueError('Engine error vtable binding changed')
    constructors=native.decode_ranges(image,{image.roots[image.containing(0x1445ef620)]})
    cr={r['address']:r for f in constructors for r in f['instructions']}
    if TABLE not in cr[0x1445ef642]['rip_references'] or cr[0x1445ef649]['operands']!='qword ptr [rcx], rax':
        raise ValueError('Engine constructor table binding changed')
    if cr[0x1445ef63b]['rip_references']!=[0x14b4f39d0]:raise ValueError('Engine global source changed')
    spec=importlib.util.spec_from_file_location('wsa_imports',HERE/'build-headless-send-drain.py')
    imports=importlib.util.module_from_spec(spec);spec.loader.exec_module(imports)
    info=imports.ordinal_import(raw,image,0x148945ad0)
    dll=Path(prior['winsock_dll']['path']);dllraw=dll.read_bytes();dllimage=native.Image(dllraw)
    exp=connect.export_name(dllraw,dllimage,info)
    if info['dll'].lower()!='ws2_32.dll' or exp['name']!='WSAGetLastError':raise ValueError('WSA import/export changed')
    fragments=prior['fragments']
    base=dict(handle=42,host='192.0.2.1',port=12345,family_tag=0,mode_byte=0,connect_return=-1,
              engine_error=0,mode_results=[True,True],wait_ok=True,ready_nonempty=True)
    fixtures=[dict(base,name='wsa-'+str(e),wsa_error=e) for e in (*range(10035,10072),0,10004,10013,10034,10072,11001)]
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fragments=fragments,code=code,constructor_fragments=constructors,
        switch_table=dict(address=JUMPS,file_offset=toff,bytes=table.hex(),sha256=hashlib.sha256(table).hexdigest(),targets=targets),
        engine_vtable=dict(address=TABLE,file_offset=voff,bytes=vbytes.hex(),sha256=hashlib.sha256(vbytes).hexdigest()),
        wsa_import=info,wsa_export=exp,winsock_dll=dict(path=str(dll),sha256=hashlib.sha256(dllraw).hexdigest()),
        cases=[Replay(raw,image,fragments,code,f).capture() for f in fixtures],native_execution=True,network_ready=False,
        limitations=[
            'Native mapper executes WSAGetLastError fixture through actual source-bound engine slot68 and connect wrapper.',
            'Only mapper code is decoded; switch data is exported/hashed separately, not mistaken for instructions.',
            'Engine constructor/global binding exported statically; other engine slots and actual startup remain fixtures.',
            'WSAGetLastError value is explicit input; real thread-local error source, syscalls and readiness not executed.',
            'No external WSA symbolic error names inferred; numeric mapping and wrapper acceptance only.',
            'Values outside native 10035..10071 switch map to default30 here, not generic OS error translation.',
            'No game launch/profile/process memory/credentials/network/Android session used.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/winsock-error-mapping-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
