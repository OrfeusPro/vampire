"""Native keyed send-B frame assembly and synchronous queue byte ownership."""
import hashlib
import importlib.util
import json
import struct
import zlib
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('send_b_blocks',HERE/'build-headless-block-decode.py')
blocks=importlib.util.module_from_spec(spec);spec.loader.exec_module(blocks)
native=blocks.stage.native;x=blocks.x
START,END=0x144aace6d,0x144aacf89
QUEUE=0x1445eac20


class SendBEmulator(blocks.BlockEmulator):
    def __init__(self):
        super().__init__()
        self.send_fragments=native.decode_ranges(self.image,
            {self.image.roots[self.image.containing(a)] for a in
             [START,QUEUE,0x144aa6330,0x144aa6060,0x1456e5740]})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva'])
                           for f in self.send_fragments)
        report=json.loads((native.ROOT/'code-clues/headless-send-frame.json').read_text('utf-8'))
        self.send_leaves=report['bodies'].copy()
        address=0x1414f51d0;off=self.image.offset(address-self.image.pe.base)
        cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
        instructions=[]
        for instruction in cs.disasm(self.raw[off:off+32],address):
            instructions.append(instruction)
            if instruction.mnemonic=='ret':break
        if not instructions or instructions[-1].mnemonic!='ret':raise ValueError('Ack ID leaf changed')
        size=instructions[-1].address+instructions[-1].size-address
        data=self.raw[off:off+size]
        self.send_leaves.append(dict(address=address,file_offset=off,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest()))
        for leaf in self.send_leaves:
            data=bytes.fromhex(leaf['bytes'])
            if self.raw[leaf['file_offset']:leaf['file_offset']+len(data)]!=data:raise ValueError('Send leaf changed')
            self.ranges.append((leaf['address'],leaf['address']+len(data)))
        rows={i['address']:i for f in self.send_fragments for i in f['instructions']}
        self.flags=rows[0x144aace76]['rip_references'][0]
        pages={p for begin,end in self.ranges for p in range(begin&~4095,(end+4095)&~4095,4096)}
        pages.update(a&~4095 for a in [self.flags,0x1495046f0,0x1498d66c0,0x1498d5e90])
        regions=list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in regions):continue
            self.uc.mem_map(page,4096)
            off=self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page,self.raw[off:off+4096])
        self.uc.mem_write(self.flags,struct.pack('<I',1))
        self.packet_tables=[]
        for address in [0x1498d66c0,0x1498d5e90]:
            off=self.image.offset(address-self.image.pe.base)
            self.packet_tables.append(dict(address=address,file_offset=off,bytes=self.raw[off:off+0x30].hex()))
        self.wake_address=self.scratch+0x3c000

    def hook(self,uc,address,size,user):
        b=self.scratch
        if address in (0x144aace88,0x144aacee8):
            # Constructors are native; allocation/capacity supplied immediately after.
            rbp=uc.reg_read(x.UC_X86_REG_RBP)
            archive=rbp-9 if address==0x144aace88 else rbp-0x49
            buffer=b+0x8000 if address==0x144aace88 else b+0x9000
            uc.mem_write(archive+0x18,struct.pack('<QQQ',buffer,buffer,buffer+256))
            uc.mem_write(archive+0x30,struct.pack('<III',256,0,0))
        if address==QUEUE:self.queue_calls+=1
        if address==self.wake_address:
            if (uc.reg_read(x.UC_X86_REG_RCX),uc.reg_read(x.UC_X86_REG_RDX))!=(b+0x4050,b+0x4110):
                raise ValueError('Queue wakeup arguments changed')
            self.wake_calls+=1
            stack=uc.reg_read(x.UC_X86_REG_RSP)
            target=struct.unpack('<Q',bytes(uc.mem_read(stack,8)))[0]
            uc.reg_write(x.UC_X86_REG_RSP,stack+8);uc.reg_write(x.UC_X86_REG_RIP,target);return
        super().hook(uc,address,size,user)

    def execute_send(self,kind,values,sequence,key,existing=b'',wake=False):
        if kind not in ('ping','key_ack') or len(existing)>1024:raise ValueError('Evidence bounds')
        uc=self.uc;b=self.scratch;packet=b+0x1000;peer=b+0x4000;queue=b+0xa000
        rbp=b+0x18079;outer=rbp-0x49
        self.copy_sizes=[];self.io_entries=[];self.queue_calls=self.wake_calls=0
        uc.mem_write(packet,bytes(64))
        uc.mem_write(packet,struct.pack('<Q',0x1498d66c0 if kind=='ping' else 0x1498d5e90))
        payload=struct.pack('<QQ',*values) if kind=='ping' else struct.pack('<Q',values[0])
        uc.mem_write(packet+0x10,payload)
        uc.mem_write(peer,bytes(0x400))
        uc.mem_write(peer+0x108,struct.pack('<I',1))
        uc.mem_write(peer+0xc0,struct.pack('<I',0 if wake else 1))
        uc.mem_write(peer+0x50,struct.pack('<Q',b+0x6000))
        uc.mem_write(b+0x6020,struct.pack('<Q',self.wake_address))
        uc.mem_write(peer+0x240,struct.pack('<H',sequence))
        uc.mem_write(peer+0x248,struct.pack('<Q',key))
        # A pristine vector has begin==end; existing data includes its sentinel.
        uc.mem_write(peer+0x178,struct.pack('<QQQ',queue,queue+len(existing)+(1 if existing else 0),queue+4096))
        uc.mem_write(queue,existing+b'\0')
        uc.mem_write(b+0x18000,bytes(0x200))
        for reg,value in [(x.UC_X86_REG_RBP,rbp),(x.UC_X86_REG_RSP,b+0x18000),
                          (x.UC_X86_REG_RDI,packet),(x.UC_X86_REG_R14,peer)]:uc.reg_write(reg,value)
        uc.emu_start(START,END,count=50000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=END:raise ValueError('Send-B budget exceeded')
        size=struct.unpack('<I',bytes(uc.mem_read(outer+0x38,4)))[0]
        frame=bytes(uc.mem_read(b+0x9000,size))
        queue_end=struct.unpack('<Q',bytes(uc.mem_read(peer+0x180,8)))[0]
        if not queue+1<=queue_end<=queue+4096:raise ValueError('Queue end outside bounds')
        queued=bytes(uc.mem_read(queue,queue_end-queue-1))
        result=uc.reg_read(x.UC_X86_REG_RBX)&0xff
        after=struct.unpack('<H',bytes(uc.mem_read(peer+0x240,2)))[0]
        # Simulate source archive disposal/reuse and a later key update.
        uc.mem_write(b+0x9000,bytes([0xcc])*size)
        uc.mem_write(peer+0x248,struct.pack('<Q',key^1))
        if bytes(uc.mem_read(queue,len(queued)))!=queued:raise ValueError('Queue borrowed frame storage')
        if queued!=existing+frame or result!=1 or self.queue_calls!=1 or self.wake_calls!=int(wake):
            raise ValueError('Synchronous queue append differs')
        return dict(kind=kind,values=list(values),sequence=sequence,sequence_after=after,test_key_bits=key,
                    existing_hex=existing.hex(),frame_hex=frame.hex(),queued_hex=queued.hex(),
                    wake=wake,queue_owns_bytes=True,queue_result=result)


def main():
    from vampir_core.frame_primitives import xor_transform
    emulator=SendBEmulator();cases=[]
    for key in [0,1,0x1020304050607080,0xffffffffffffffff]:
        for sequence in [0,1,255,256,65535]:
            for kind,values in [('ping',(0x0102030405060708,0xffffffffffffffff)),('key_ack',(0x1122334455667788,))]:
                case=emulator.execute_send(kind,values,sequence,key,existing=b'prior:',wake=bool(sequence&1))
                payload=struct.pack('<QQ',*values) if kind=='ping' else struct.pack('<Q',values[0])
                inner=struct.pack('<HH',16 if kind=='ping' else 12,sequence)+payload
                clear=struct.pack('<I',zlib.crc32(inner))+inner
                expected=(len(clear)+3).to_bytes(3,'little')+xor_transform(clear,key)
                if case['frame_hex']!=expected.hex() or case['sequence_after']!=(sequence+1)&65535:
                    raise ValueError('Native send-B layout differs')
                cases.append(case)
    report=dict(schema_version=1,source=emulator.bindings['source'],sha256=emulator.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=emulator.send_fragments,leaves=emulator.send_leaves,packet_tables=emulator.packet_tables,
                slice_start=START,slice_end=END,cases=cases,statistics=dict(native_send_b_cases=len(cases)),network_ready=False,
                limitations=['Native send-B ID/sequence/writers/CRC/XOR and synchronous queue append executed.',
                'Archive/vector capacities explicitly preallocated; only CRT memory functions and wake callback shimmed.',
                'Queue owns copied ciphertext before return; source invalidation/key change simulated after slice.',
                'Actual archive destructor, allocator growth, queue drain/socket write and wake scheduling excluded.',
                'Ping and KeyChanged only; key values synthetic, no full Notify-handler-to-wire replay or live server proof.'])
    path=native.ROOT/'code-clues/headless-send-b.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(dict(output=str(path),**report['statistics'],network_ready=False)))


if __name__=='__main__':main()
