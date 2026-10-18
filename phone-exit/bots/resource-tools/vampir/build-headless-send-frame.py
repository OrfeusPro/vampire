"""Execute the native send-A frame assembly slice with explicit preallocated archives."""
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('send_ping',HERE/'build-headless-ping-codec.py')
ping=importlib.util.module_from_spec(spec);spec.loader.exec_module(ping)
from unicorn import x86_const as x
native=ping.native
START,END=0x144aa9e6a,0x144aa9f45


class SendFrameEmulator(ping.PingEmulator):
    def __init__(self):
        super().__init__()
        self.extra_fragments=native.decode_ranges(self.image,
            {self.image.roots[self.image.containing(a)] for a in (0x144aa6330,START,0x144aa6060)})
        self.extra_bodies=[]
        spans=[(0x144aa5f80,0x144aa5f8e),(0x1418ba360,0x1418ba36a),
               (0x1445f1230,0x1445f1267),(0x144aa6ca0,0x144aa6cf4),
               (0x1414079a0,0x1414079a6)]
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva'])
                           for f in self.extra_fragments)
        self.ranges.extend(spans)
        pages=set()
        for begin,end in self.ranges:
            pages.update(range(begin&~4095,(end+4095)&~4095,4096))
        pages.update([0x149504000,0x1498d6000])
        # mem_regions may merge adjacent pages; inspect coverage instead of only region starts.
        regions=list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(begin<=page<=end for begin,end,_ in regions):continue
            self.uc.mem_map(page,4096)
            offset=self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page,self.raw[offset:offset+4096])
            self.uc.mem_protect(page,4096,ping.unicorn.UC_PROT_READ|ping.unicorn.UC_PROT_EXEC)
        for begin,end in spans:
            offset=self.image.offset(begin-self.image.pe.base)
            content=self.raw[offset:offset+end-begin]
            self.extra_bodies.append(dict(address=begin,file_offset=offset,bytes=content.hex(),
                                          sha256=hashlib.sha256(content).hexdigest()))
        self.slice_rows=[i for f in self.extra_fragments for i in f['instructions']
                         if START<=i['address']<END]
        if not self.slice_rows or self.slice_rows[0]['address']!=START or (
            self.slice_rows[-1]['address']+len(bytes.fromhex(self.slice_rows[-1]['bytes'])))!=END:
            raise ValueError('Assembly slice boundaries changed')
        if self.raw[self.image.offset(END-self.image.pe.base):][:3]!=bytes.fromhex('488d4d'):
            raise ValueError('Post-transform terminal changed')

    def execute_frame(self,values,sequence):
        uc=self.uc;b=self.scratch;obj=b+0x1000;connection=b+0x4000
        rbp=b+0x18079;inner=rbp+7;outer=rbp-0x39
        self.copy_sizes=[];self.io_entries=[]
        uc.mem_write(obj,b'\0'*64)
        uc.mem_write(obj,struct.pack('<Q',0x1498d66c0))
        uc.mem_write(obj+0x10,struct.pack('<QQ',*values))
        uc.mem_write(connection+0x228,struct.pack('<H',sequence))
        for archive,buffer in [(inner,b+0x8000),(outer,b+0xa000)]:
            uc.mem_write(archive,b'\0'*64)
            self.call(0x144aa62f0,archive,1)
            uc.mem_write(archive+0x18,struct.pack('<QQQ',buffer,buffer,buffer+256))
            uc.mem_write(archive+0x30,struct.pack('<III',256,0,0))
        for reg,value in [(x.UC_X86_REG_RBP,rbp),(x.UC_X86_REG_RSP,b+0x18000),
                          (x.UC_X86_REG_RDI,obj),(x.UC_X86_REG_R14,connection)]:
            uc.reg_write(reg,value)
        uc.emu_start(START,END,count=20000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=END:raise ValueError('Send slice did not terminate')
        length=struct.unpack('<I',bytes(uc.mem_read(outer+0x38,4)))[0]
        frame=bytes(uc.mem_read(b+0xa000,length))
        sequence_after=struct.unpack('<H',bytes(uc.mem_read(connection+0x228,2)))[0]
        return dict(values=list(values),sequence=sequence,sequence_after=sequence_after,
                    frame_hex=frame.hex(),copy_sizes=self.copy_sizes.copy(),native_io_entries=self.io_entries.copy())


def main():
    emulator=SendFrameEmulator();cases=[]
    for first,second in [(0,0),(1,2),(0x0102030405060708,2**53+1),(2**64-1,2**64-1)]:
        for sequence in [0,1,255,256,65535]:
            case=emulator.execute_frame((first,second),sequence)
            # Independent construction; this does not replace any native assembly stage.
            import zlib
            inner=struct.pack('<HHQQ',16,sequence,first,second)
            clear=len(inner+bytes(7)).to_bytes(3,'little')+struct.pack('<I',zlib.crc32(inner))+inner
            key=bytes.fromhex('a78420d0c978b39a')
            expected=clear[:3]+bytes(v^key[i&7] for i,v in enumerate(clear[3:]))
            if case['frame_hex']!=expected.hex() or case['sequence_after']!=(sequence+1)&65535:
                raise ValueError('Native complete send-A assembly differs')
            cases.append(case)
    report=dict(schema_version=1,source=emulator.bindings['source'],sha256=emulator.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                upstreams=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in
                           [native.ROOT/'code-clues/headless-ping-codec.json',
                            native.ROOT/'code-clues/headless-frame-primitives.json']],
                fragments=emulator.extra_fragments,bodies=emulator.extra_bodies,
                slice_start=START,slice_end=END,slice_instructions=emulator.slice_rows,cases=cases,
                statistics=dict(native_send_scenarios=len(cases)),send_a_layout_verified=True,
                receive_validation_verified=False,network_ready=False,
                limitations=['Real send-A assembly slice executed, including packet ID/sequence/body, length, CRC and XOR.',
                             'Archives explicitly constructed and preallocated; buffer growth/socket/session setup excluded.',
                             'Only external CRT memcpy shimmed, via the existing Ping emulator.',
                             'Ping payload cases only; no claim of complete login schema, send-B session key or server compatibility.',
                             'No live server traffic or receive validation executed.'])
    path=native.ROOT/'code-clues/headless-send-frame.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(dict(output=str(path),**report['statistics'],send_a_layout_verified=True,network_ready=False)))


if __name__=='__main__':main()
