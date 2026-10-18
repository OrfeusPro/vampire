"""Replay native transport receive staging: size23, compression and buffer compaction."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('stage_ping',HERE/'build-headless-ping-codec.py')
ping=importlib.util.module_from_spec(spec);spec.loader.exec_module(ping)
native=ping.native
from unicorn import x86_const as x

START,END=0x1445ed403,0x1445ed562
MEMMOVE,MEMSET=0x1487a2e1f,0x1487a2e25
DECOMPRESS=0x14141ba60


def literal_block(data):
    """Explicit literal-only block fixture, not a general compressor."""
    count=len(data);result=bytearray([min(count,15)<<4])
    if count>=15:
        remaining=count-15
        while remaining>=255:result.append(255);remaining-=255
        result.append(remaining)
    return bytes(result)+data


class TransportStageEmulator(ping.PingEmulator):
    def __init__(self):
        super().__init__()
        addresses=[START,0x1445e4a90,0x1445de6e0,DECOMPRESS]
        self.stage_fragments=native.decode_ranges(self.image,
            {self.image.roots[self.image.containing(a)] for a in addresses})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva'])
                           for f in self.stage_fragments)
        pages=set()
        for begin,end in self.ranges:pages.update(range(begin&~4095,(end+4095)&~4095,4096))
        regions=list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in regions):continue
            self.uc.mem_map(page,4096)
            off=self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page,self.raw[off:off+4096])
            self.uc.mem_protect(page,4096,ping.unicorn.UC_PROT_READ|ping.unicorn.UC_PROT_EXEC)
        rows={i['address']:i for f in self.stage_fragments for i in f['instructions']}
        self.tls_index=rows[0x1445ed42b]['rip_references'][0]
        self.uc.mem_map(self.tls_index&~4095,4096)
        self.uc.mem_write(self.tls_index,struct.pack('<I',0))
        checks=[(0x1445ed483,'and','ebx, 0x7fffff'),
                (0x1445ed497,'shr','eax, 0x17'),
                (0x1445ed4ae,'mov','r9d, 0x100000'),
                (0x1445ed4b4,'call','0x14141ba60'),
                (0x1445ed4dd,'movsxd','rax, dword ptr [rdi + 0x1fc]'),
                (0x1445ed4ea,'lea','rsi, [r10 + rax]'),
                (0x1445ed4f8,'call','0x1445e4a90'),
                (0x1445ed52e,'call','0x1487a2e1f')]
        for address,mnemonic,operands in checks:
            if (rows[address]['mnemonic'],rows[address]['operands'])!=(mnemonic,operands):
                raise ValueError('Transport stage anchor changed')
        diagnostic=rows[0x1445ed4cc]['rip_references'][0]
        off=self.image.offset(diagnostic-self.image.pe.base)
        if self.raw[off:off+len(b'UxTcpPeer::_HandleRecvBuffer\0')]!=b'UxTcpPeer::_HandleRecvBuffer\0':
            raise ValueError('Transport diagnostic changed')
        # Confirm external memory shims through import directory.
        sp=importlib.util.spec_from_file_location('stage_imports',HERE/'build-object-zero-init-code.py')
        imports=importlib.util.module_from_spec(sp);sp.loader.exec_module(imports)
        self.memory_imports=[]
        for address,name in [(MEMMOVE,'memmove'),(MEMSET,'memset')]:
            off=self.image.offset(address-self.image.pe.base)
            if self.raw[off:off+2]!=b'\xff\x25':raise ValueError('Memory import thunk changed')
            target=address+6+struct.unpack_from('<i',self.raw,off+2)[0]
            info=imports.import_at(self.raw,self.image,target)
            if info['name']!=name:raise ValueError('Unexpected memory import')
            self.memory_imports.append(info)

    def hook(self,uc,address,size,user):
        if address in (MEMMOVE,MEMSET):
            destination=uc.reg_read(x.UC_X86_REG_RCX);argument=uc.reg_read(x.UC_X86_REG_RDX)
            length=uc.reg_read(x.UC_X86_REG_R8)
            if length>4096 or not self.scratch<=destination<=self.scratch+0x40000-length:
                raise ValueError('Memory shim bound')
            if address==MEMMOVE:
                if not self.scratch<=argument<=self.scratch+0x40000-length:raise ValueError('Source bound')
                data=bytes(uc.mem_read(argument,length))
            else:data=bytes([argument&255])*length
            if data:uc.mem_write(destination,data)
            uc.reg_write(x.UC_X86_REG_RAX,destination)
            stack=uc.reg_read(x.UC_X86_REG_RSP)
            ret=struct.unpack('<Q',bytes(uc.mem_read(stack,8)))[0]
            uc.reg_write(x.UC_X86_REG_RSP,stack+8);uc.reg_write(x.UC_X86_REG_RIP,ret)
            return
        if address==DECOMPRESS:self.decompress_calls+=1
        super().hook(uc,address,size,user)

    def execute_stage(self,stream,skip=3,existing=b''):
        if len(stream)>2048 or len(existing)>1024:raise ValueError('Evidence bound')
        uc=self.uc;b=self.scratch;owner=b+0x1000;source=b+0x8000;output=b+0x18000
        self.copy_sizes=[];self.io_entries=[];self.decompress_calls=0
        uc.mem_write(owner,b'\0'*0x300)
        uc.mem_write(source,stream+b'\0')
        uc.mem_write(output,existing+b'\0')
        # Native byte vectors include a trailing NUL sentinel in end pointers.
        uc.mem_write(owner+0x198,struct.pack('<QQQ',output,output+len(existing)+1,output+4096))
        uc.mem_write(owner+0x1b8,struct.pack('<QQQ',source,source+len(stream)+1,source+4096))
        uc.mem_write(owner+0x1fc,struct.pack('<I',skip))
        tls_array=b+0x3000;tls_block=b+0x10000;gs=b+0x2000
        uc.reg_write(x.UC_X86_REG_GS_BASE,gs)
        uc.mem_write(gs+0x58,struct.pack('<Q',tls_array));uc.mem_write(tls_array,struct.pack('<Q',tls_block))
        for reg,value in [(x.UC_X86_REG_RCX,owner),(x.UC_X86_REG_RDI,owner),
                          (x.UC_X86_REG_R8,source),(x.UC_X86_REG_R9,source+len(stream)+1),
                          (x.UC_X86_REG_R15,0),(x.UC_X86_REG_RSP,b+0x30000)]:uc.reg_write(reg,value)
        uc.emu_start(START,END,count=50000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=END:raise ValueError('Stage budget exceeded')
        source_end=struct.unpack('<Q',bytes(uc.mem_read(owner+0x1c0,8)))[0]
        output_end=struct.unpack('<Q',bytes(uc.mem_read(owner+0x1a0,8)))[0]
        remaining=bytes(uc.mem_read(source,source_end-source-1))
        emitted=bytes(uc.mem_read(output,output_end-output-1))
        return dict(stream_hex=stream.hex(),skip=skip,existing_hex=existing.hex(),
                    remaining_hex=remaining.hex(),output_hex=emitted.hex(),decompress_calls=self.decompress_calls)


def main():
    emulator=TransportStageEmulator();cases=[]
    payloads=[b'A',b'hello',bytes(range(16)),bytes(range(64)),bytes(range(256))]
    def frame(payload,compressed):
        body=literal_block(payload) if compressed else payload
        return ((len(body)+3)|(0x800000 if compressed else 0)).to_bytes(3,'little')+body
    for payload in payloads:
        for compressed in [False,True]:
            raw=frame(payload,compressed)
            for split in sorted({0,1,2,3,len(raw)-1,len(raw)}):
                case=emulator.execute_stage(raw[:split])
                complete=split==len(raw)
                if case['output_hex']!=(payload if complete else b'').hex() or case['remaining_hex']!=(b'' if complete else raw[:split]).hex():
                    raise ValueError('Native staging/fragment behavior differs')
                cases.append(case)
    for compressed in [False,True]:
        raw=frame(b'first',compressed)+frame(b'second',not compressed)+b'\x05\x00'
        case=emulator.execute_stage(raw,existing=b'prior:')
        if case['output_hex']!=b'prior:firstsecond'.hex() or case['remaining_hex']!='0500':
            raise ValueError('Native coalesced frame staging differs')
        cases.append(case)
    raw=frame(b'kept-header',False)
    case=emulator.execute_stage(raw,skip=0)
    if case['output_hex']!=raw.hex():raise ValueError('Native skip=0 differs')
    cases.append(case)
    report=dict(schema_version=1,source=emulator.bindings['source'],sha256=emulator.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=emulator.stage_fragments,memory_imports=emulator.memory_imports,
                slice_start=START,slice_end=END,cases=cases,
                statistics=dict(native_stage_cases=len(cases)),network_ready=False,
                limitations=['Native first receive staging slice only; listeners/callback loop excluded.',
                             'Source/output byte vectors and TLS explicitly initialized with bounded preallocation.',
                             'Native decompressor executed on literal-only block fixtures; general compressed grammar not implemented.',
                             'Only CRT memcpy/memmove/memset shimmed; allocator growth excluded.',
                             'Second-layer frame layout/CRC policy and transport socket execution unresolved.'])
    path=native.ROOT/'code-clues/headless-transport-stage.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(dict(output=str(path),**report['statistics'],network_ready=False)))


if __name__=='__main__':main()
