"""Native Dispatch/VersionResult reader/handler and bounded result gate paths."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('version_dispatch',HERE/'build-headless-dispatch.py')
dispatch=importlib.util.module_from_spec(spec);spec.loader.exec_module(dispatch)
native,x=dispatch.native,dispatch.x
CTOR,READER,HANDLER=0x1456d5460,0x1456d9b10,0x146768360
PACKET_TABLE,HANDLER_TABLE=0x1498d69f0,0x149d81170
GATE,LOGIN=0x1467a8e10,0x1467a9700


class Emulator(dispatch.DispatchEmulator):
    def __init__(self):
        super().__init__()
        self.extra=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in (READER,HANDLER,0x144aa5c10,0x1456e3a40,0x14678ec40,LOGIN)})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.extra)
        self.version_leaves=[]
        cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
        for address,size in ((CTOR,0x29),(0x141484e40,6),(GATE,0x8e),(0x1467a91d6,0x51)):
            off=self.image.offset(address-self.image.pe.base);data=self.raw[off:off+size];rows=[]
            for i in cs.disasm(data,address):
                refs=[i.address+i.size+op.mem.disp for op in i.operands if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
                rows.append(dict(address=i.address,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=refs))
            if sum(len(bytes.fromhex(r['bytes'])) for r in rows)!=size:raise ValueError('Version result bounded decode changed')
            self.version_leaves.append(dict(address=address,file_offset=off,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest(),instructions=rows))
            self.ranges.append((address,address+size))
        if self.version_leaves[1]['bytes']!='b802000000c3':raise ValueError('Version result ID changed')
        self.version_hooks={0x14142d840,0x141424430,0x14147d580,0x141421150,0x1413fe190,
            0x14558edf0,0x145f8a7a0,0x144aaa9d0,LOGIN}
        rows=[r for f in self.extra for r in f['instructions']]+[r for f in self.version_leaves for r in f['instructions']]
        pages={a&~4095 for r in rows for a in (r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references'])}
        pages.update(a&~4095 for a in (*self.version_hooks,PACKET_TABLE,HANDLER_TABLE))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])
        self.handler_table=HANDLER_TABLE

    def hook(self,uc,address,size,user):
        if address==GATE:
            code,packet_id,mode=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R9)]
            if packet_id!=2 or mode:raise ValueError('Version result gate ID/mode changed')
            self.version_events.append(dict(action='native_result_gate',code=code,packet_id=packet_id))
        if address==0x14676845c:
            self.version_events.append(dict(action='native_result_gate_return',al=uc.reg_read(x.UC_X86_REG_AL)))
        if address==HANDLER:
            b=self.scratch
            args=tuple(uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8))
            if args!=(b+0x7000,0x12345678,b+0x7100):raise ValueError('Version handler args changed')
            if int.from_bytes(uc.mem_read(b+0x5048,8),'little')!=b+0x7100 or int.from_bytes(uc.mem_read(self.tls_block+0x100cc0,8),'little')!=b+0x5000:raise ValueError('Version active context/TLS changed')
            self.version_events.append(dict(action='native_version_handler',values=list(struct.unpack('<IIBII',bytes(uc.mem_read(b+0x7110,8))+bytes(uc.mem_read(b+0x7118,1))+bytes(uc.mem_read(b+0x711c,8))))))
        if address in self.version_hooks:
            a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
            result=0
            if address in (0x14142d840,0x141421150):uc.mem_write(a,b'\0'*16)
            elif address in (0x141424430,0x14147d580,0x1413fe190):pass
            elif address==0x14558edf0:result=self.scratch+0x7600
            elif address==0x145f8a7a0:self.version_events.append(dict(action='result_error_helper_capture',code=a,raw_mode=b))
            elif address==0x144aaa9d0:result=self.scratch+0x7800
            elif address==LOGIN:
                if a!=self.scratch+0x7800:raise ValueError('Version success target this changed')
                self.version_events.append(dict(action='login_routine_entry_capture'))
            uc.reg_write(x.UC_X86_REG_RAX,result);self.ret(uc);return
        setup=address==dispatch.listener.START and self.setup_pending
        super().hook(uc,address,size,user)
        if setup:uc.mem_write(self.scratch+0x7410,struct.pack('<H',2))

    def execute_version(self,payload,flag=0,packet_id=2):
        from vampir_core.frame_primitives import xor_transform
        self.copy_sizes=[];self.io_entries=[];self.handler_events=[];self.unknown_ids=[];self.version_events=[]
        self.decode_failures=self.cookie_checks=0
        self.uc.mem_write(self.scratch+0x7608,bytes([flag]))
        self.call(CTOR,self.scratch+0x7100)
        plain=struct.pack('<H',packet_id)+payload
        frame=(len(plain)+3).to_bytes(3,'little')+xor_transform(plain)
        self.setup_pending=True;case=self.execute_listener(frame)
        current=int.from_bytes(self.uc.mem_read(self.scratch+0x5048,8),'little')
        tls=int.from_bytes(self.uc.mem_read(self.tls_block+0x100cc0,8),'little')
        if current or tls or self.cookie_checks!=1:raise ValueError('Version Dispatch cleanup changed')
        return dict(payload_hex=payload.hex(),state_flag=flag,packet_id=packet_id,events=self.version_events.copy(),
            decode_failures=self.decode_failures,unknown_ids=self.unknown_ids.copy(),remaining_hex=case['remaining_hex'],context_cleared=True)


def build():
    upstream=native.ROOT/'code-clues/version-send-path-replay.json';prior=json.loads(upstream.read_text('utf-8'))
    em=Emulator()
    if prior['sha256']!=em.bindings['sha256']:raise ValueError('Version result source mismatch')
    packet_bindings_path=native.ROOT/'code-clues/headless-packet-bindings.json'
    packet_bindings=json.loads(packet_bindings_path.read_text('utf-8'))
    login_binding=next(p for p in packet_bindings['packets'] if p['name']=='PktLogin')
    if packet_bindings['sha256']!=prior['sha256'] or login_binding['constructor']!=0x1456d4c80:raise ValueError('Login packet binding changed')
    rows={r['address']:r for f in em.extra for r in f['instructions']}
    for address,target in ((0x14678ec9c,CTOR),(0x14678ecaf,0x1467a7250),(0x146768457,GATE),(0x146768468,LOGIN),(0x1467a97fd,0x1456d4c80)):
        if rows[address]['operands']!=hex(target):raise ValueError('Version result direct call binding changed')
    if rows[0x14678ec7b]['rip_references']!=[HANDLER_TABLE]:raise ValueError('Version result registration table changed')
    tables=[]
    for address,checks,size in ((PACKET_TABLE,{0x20:READER,0x28:0x141484e40,0x38:0x1456e3a40},64),
        (HANDLER_TABLE,{8:dispatch.WRAPPER,16:HANDLER},24)):
        off=em.image.offset(address-em.image.pe.base);data=em.raw[off:off+size]
        if any(struct.unpack_from('<Q',data,slot)[0]!=target for slot,target in checks.items()):raise ValueError('Version result vtable changed')
        tables.append(dict(address=address,file_offset=off,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest()))
    name_address=rows[0x1456e3a49]['rip_references'][0];off=em.image.offset(name_address-em.image.pe.base)
    name_bytes=em.raw[off:off+17]
    if name_bytes!=b'PktVersionResult\0':raise ValueError('Version result name changed')
    if em.version_leaves[0]['instructions'][0]['rip_references']!=[PACKET_TABLE] or em.version_leaves[0]['instructions'][1]['operands']!='qword ptr [rcx], rax':raise ValueError('Version result ctor table install changed')
    cases=[]
    for code in (0,1,42,708,1304,0xffffffff):
        for flag in (0,1):cases.append(em.execute_version(struct.pack('<IIBII',code,0x12345678,1,207,2),flag))
    for boolean in (0,1,2,255):cases.append(em.execute_version(struct.pack('<IIBII',0,0xffffffff,boolean,0xffffffff,0xffffffff)))
    cases.append(em.execute_version(bytes(17)+b'extra'))
    cases.extend(em.execute_version(bytes(n)) for n in range(17))
    cases.extend(em.execute_version(bytes(17),packet_id=i) for i in (0,1,3,17,65535))
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(upstream.read_bytes()).hexdigest(),
        fragments=em.extra,leaves=em.version_leaves,tables=tables,
        packet_name=dict(address=name_address,file_offset=off,bytes=name_bytes.hex(),name='PktVersionResult'),
        login_packet_binding=login_binding,packet_bindings_sha256=hashlib.sha256(packet_bindings_path.read_bytes()).hexdigest(),
        cases=cases,native_execution=True,network_ready=False,
        limitations=['Actual receive-A/Dispatch/VersionResult constructor/reader/handler and selected native gate paths execute.',
            'Synthetic one-bucket ID2 registry; source registration checked but factory not executed.',
            'State getter/diagnostics/error helper/singleton getter fixtures; Login routine captured at entry.',
            'Gate head/tail bounded around covered codes; other UI/policy branches and switch data not executed.',
            'Short-reader diagnostic skipped as prior Dispatch replay; native TLS reset/archive cleanup execute.',
            'Trailing bytes accepted by native reader; bool normalizes any nonzero byte.',
            'Receive-A isolated input is not proof live game selects A rather than B; no CRC/real negotiation/session.',
            'No game launch/profile/process memory/credentials/network or Android execution.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/version-result-handler-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
