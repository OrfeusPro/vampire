"""Replay native CRC32 and repeating XOR helpers with byte-level provenance."""
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]/'.tools/vampir-analysis'))
import unicorn
from unicorn import x86_const as x

spec = importlib.util.spec_from_file_location('frame_calls',HERE/'build-entry-window-code.py')
calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calls)
native = calls.native

CRC_INIT, CRC, XOR = 0x1418ba360, 0x1445f1230, 0x144aa6ca0
CRC_TABLE = 0x1495046f0
FALLBACK = 0x9ab378c9d02084a7
ROOTS = [0x144aa9da0,0x144aaccf0,0x144aa9c00,0x144aacb50]


def reference_crc(data):
    state=0xffffffff
    for byte in data:
        state ^= byte
        for _ in range(8):
            state=(state>>1) ^ (0xedb88320 if state&1 else 0)
    return state ^ 0xffffffff


class FramePrimitiveEmulator:
    def __init__(self):
        if native.capstone.__version__!='5.0.6' or unicorn.__version__!='2.1.4':
            raise ValueError('Use pinned analysis dependencies')
        self.upstream=native.ROOT/'code-clues/headless-ping-codec.json'
        self.source=json.loads(self.upstream.read_text('utf-8'))
        self.raw=Path(self.source['source']).read_bytes()
        if hashlib.sha256(self.raw).hexdigest()!=self.source['sha256']:
            raise ValueError('Client changed')
        self.image=native.Image(self.raw)
        self.fragments=native.decode_ranges(self.image,
            {self.image.roots[self.image.containing(a)] for a in ROOTS})
        rows={i['address']:i for f in self.fragments for i in f['instructions']}
        # Direct calls prove helper entry addresses; no guessed prologue scanning.
        for site,target in [(0x144aa9ec2,CRC_INIT),(0x144aa9f00,CRC),(0x144aa9f40,XOR),
                            (0x144aacf1c,CRC),(0x144aacf63,XOR),
                            (0x144aa9c2c,XOR),(0x144aacb83,XOR)]:
            if not calls.checked_call(rows.get(site),target):
                raise ValueError('Helper caller changed '+hex(site))
        self.anchors=[]
        self.ranges=[]
        decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
        # Selected call-target entries are leaf routines; decode until their first RET.
        for address in (CRC_INIT,CRC,XOR):
            offset=self.image.offset(address-self.image.pe.base)
            instructions=[]
            for i in decoder.disasm(self.raw[offset:offset+256],address):
                instructions.append(i)
                if i.mnemonic=='ret':break
                if i.mnemonic=='call':raise ValueError('Unexpected leaf call')
            if not instructions or instructions[-1].mnemonic!='ret':
                raise ValueError('Missing bounded helper return')
            size=instructions[-1].address+instructions[-1].size-address
            content=self.raw[offset:offset+size]
            self.anchors.append(dict(address=address,file_offset=offset,bytes=content.hex(),
                                     sha256=hashlib.sha256(content).hexdigest()))
            self.ranges.append((address,address+size))
        table_offset=self.image.offset(CRC_TABLE-self.image.pe.base)
        table=self.raw[table_offset:table_offset+1024]
        expected=[]
        for value in range(256):
            for _ in range(8):value=(value>>1)^(0xedb88320 if value&1 else 0)
            expected.append(value)
        if struct.unpack('<256I',table)!=tuple(expected):
            raise ValueError('CRC table is not the reviewed polynomial')
        self.table=dict(address=CRC_TABLE,file_offset=table_offset,bytes=table.hex(),
                        sha256=hashlib.sha256(table).hexdigest())
        crc_off=self.image.offset(CRC-self.image.pe.base)
        # Pin the actual table address encoded in the native LEA, not just table contents.
        if self.raw[crc_off+8:crc_off+11]!=bytes.fromhex('4c8d1d') or (
                CRC+15+struct.unpack_from('<i',self.raw,crc_off+11)[0])!=CRC_TABLE:
            raise ValueError('Native CRC table reference changed')
        self.uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
        self.base=0x20000000
        self.uc.mem_map(self.base,0x20000)
        pages={a&~4095 for a in (CRC_INIT,CRC,XOR,CRC_TABLE)}
        for p in pages:
            self.uc.mem_map(p,4096)
            off=self.image.offset(p-self.image.pe.base)
            self.uc.mem_write(p,self.raw[off:off+4096])
            self.uc.mem_protect(p,4096,unicorn.UC_PROT_READ|
                               (unicorn.UC_PROT_EXEC if p!=CRC_TABLE&~4095 else 0))
        self.uc.hook_add(unicorn.UC_HOOK_CODE,self.guard)

    def guard(self,uc,address,size,user):
        if not any(begin<=address<end for begin,end in self.ranges):
            raise ValueError('Unreviewed native helper target')

    def call(self,address,rcx,rdx=0,r8=0,r9=0):
        uc=self.uc;stack=self.base+0x1e000;stop=self.base+0x1f000
        uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in [(x.UC_X86_REG_RCX,rcx),(x.UC_X86_REG_RDX,rdx),
                          (x.UC_X86_REG_R8,r8),(x.UC_X86_REG_R9,r9),(x.UC_X86_REG_RSP,stack)]:
            uc.reg_write(reg,value)
        uc.emu_start(address,stop,count=20000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('Helper budget exceeded')
        return uc.reg_read(x.UC_X86_REG_RAX)

    def crc(self,payload):
        if len(payload)>512:raise ValueError('Evidence buffer bound')
        source=self.base+0x1000;state=self.base+0x2000
        self.uc.mem_write(source,payload or b'\0')
        self.call(CRC_INIT,state)
        value=self.call(CRC,state,source,len(payload))
        return dict(payload_hex=payload.hex(),value=value,
                    state=struct.unpack('<I',bytes(self.uc.mem_read(state,4)))[0])

    def xor(self,payload,key=0,in_place=False):
        if len(payload)>512:raise ValueError('Evidence buffer bound')
        source=self.base+0x3000;destination=source if in_place else self.base+0x5000
        self.uc.mem_write(source,payload or b'\0')
        if not in_place:self.uc.mem_write(destination,b'\xcc'*(len(payload)+1))
        self.uc.mem_write(destination+len(payload),b'\x7b')
        returned=self.call(XOR,source,len(payload),destination,key)
        output=bytes(self.uc.mem_read(destination,len(payload)))
        if bytes(self.uc.mem_read(destination+len(payload),1))!=b'\x7b':
            raise ValueError('Helper crossed output boundary')
        return dict(payload_hex=payload.hex(),key_bits=key,in_place=in_place,
                    output_hex=output.hex(),returned=returned)


def main():
    emulator=FramePrimitiveEmulator()
    inputs=[b'',b'123456789',bytes(range(256))]
    inputs += [bytes((j*37+11)&255 for j in range(n)) for n in (1,2,3,4,7,8,9,15,16,17,31,32,33,255,256,257,511,512)]
    crc_cases=[];xor_cases=[]
    for payload in inputs:
        crc=emulator.crc(payload)
        if crc['value']!=reference_crc(payload) or crc['state']!=(crc['value']^0xffffffff):
            raise ValueError('Native CRC differs from independent bitwise reference')
        crc_cases.append(crc)
        for key in [0,1,0x0102030405060708,2**64-1,FALLBACK]:
            key_bytes=(key or FALLBACK).to_bytes(8,'little')
            expected=bytes(byte^key_bytes[i&7] for i,byte in enumerate(payload))
            for in_place in [False,True]:
                case=emulator.xor(payload,key,in_place)
                if bytes.fromhex(case['output_hex'])!=expected or case['returned']!=len(payload):
                    raise ValueError('Native XOR differs from reference')
                xor_cases.append(case)
    report=dict(schema_version=1,source=emulator.source['source'],sha256=emulator.source['sha256'],
                upstream_sha256=hashlib.sha256(emulator.upstream.read_bytes()).hexdigest(),
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=emulator.fragments,helper_bodies=emulator.anchors,crc_table=emulator.table,
                crc_cases=crc_cases,xor_cases=xor_cases,
                statistics=dict(crc_cases=len(crc_cases),xor_cases=len(xor_cases),
                                native_executions=2*len(crc_cases)+len(xor_cases)),
                fallback_key_bits=FALLBACK,full_frame_verified=False,network_ready=False,
                limitations=['Native CRC constructor/update and XOR helper executed without shims.',
                             'Explicit inputs, no live session keys or credentials.',
                             'Only exact same-buffer and disjoint-buffer XOR overlap modes verified.',
                             'Complete send/receive frame, integrity enforcement and key source remain unresolved.'])
    path=native.ROOT/'code-clues/headless-frame-primitives.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(dict(output=str(path),**report['statistics'],network_ready=False)))


if __name__=='__main__':main()
