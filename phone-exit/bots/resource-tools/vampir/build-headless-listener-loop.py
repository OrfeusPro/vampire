"""Replay native second receive loop with frozen listener lifetime fixtures."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('listener_blocks',HERE/'build-headless-block-decode.py')
blocks=importlib.util.module_from_spec(spec);spec.loader.exec_module(blocks)
native=blocks.stage.native
x=blocks.x
START,END=0x1445ed572,0x1445ed730
SNAPSHOT,CLEANUP,FREE,EXPIRED=0x1445e2010,0x1445ddb70,0x14142c480,0x1445dae30
PROBE,WRAPPER,XOR=0x144aa9a90,0x144aa9c00,0x144aa6ca0


class ListenerEmulator(blocks.BlockEmulator):
    def __init__(self):
        super().__init__()
        self.listener_fragments=native.decode_ranges(self.image,
            {self.image.roots[self.image.containing(a)] for a in [START,0x1445dede0,WRAPPER]})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva'])
                           for f in self.listener_fragments)
        receive=json.loads((native.ROOT/'code-clues/headless-receive-envelope.json').read_text('utf-8'))
        helpers=json.loads((native.ROOT/'code-clues/headless-frame-primitives.json').read_text('utf-8'))
        self.leaves=[receive['probe_body']]
        self.leaves.extend(a for a in helpers['helper_bodies'] if a['address']==XOR)
        for address in [0x1415f6848,0x1437113e4]:
            off=self.image.offset(address-self.image.pe.base)
            content=self.raw[off:off+6]
            self.leaves.append(dict(address=address,file_offset=off,bytes=content.hex(),
                                    sha256=hashlib.sha256(content).hexdigest()))
        for leaf in self.leaves:
            content=bytes.fromhex(leaf['bytes'])
            if self.raw[leaf['file_offset']:leaf['file_offset']+len(content)]!=content:
                raise ValueError('Leaf provenance changed')
            self.ranges.append((leaf['address'],leaf['address']+len(content)))
        pages={p for begin,end in self.ranges for p in range(begin&~4095,(end+4095)&~4095,4096)}
        self.table=receive['receive_tables'][0]
        pages.add(self.table['table']&~4095)
        pages.update(address&~4095 for address in [SNAPSHOT,CLEANUP,FREE,EXPIRED])
        regions=list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in regions):continue
            self.uc.mem_map(page,4096)
            off=self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page,self.raw[off:off+4096])
            self.uc.mem_protect(page,4096,blocks.stage.ping.unicorn.UC_PROT_READ|blocks.stage.ping.unicorn.UC_PROT_EXEC)
        self.capture_address=self.scratch+0x3d000

    def ret(self,uc):
        stack=uc.reg_read(x.UC_X86_REG_RSP)
        target=struct.unpack('<Q',bytes(uc.mem_read(stack,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,stack+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def hook(self,uc,address,size,user):
        b=self.scratch
        if address in (SNAPSHOT,CLEANUP,FREE,EXPIRED,self.capture_address):
            rcx=uc.reg_read(x.UC_X86_REG_RCX);rdx=uc.reg_read(x.UC_X86_REG_RDX)
            if address==SNAPSHOT:
                if rdx!=self.owner+8 or not b+0x2f000<=rcx<b+0x30100:
                    raise ValueError('Snapshot fixture arguments changed')
                uc.mem_write(rcx,struct.pack('<QQQQQ',b+0x6000,b+0x6100,4,0,self.listener_count))
                self.snapshot_count+=1
            elif address==CLEANUP:
                if not b+0x2f000<=rcx<b+0x30100:raise ValueError('Cleanup fixture bound')
                self.cleanup_count+=1
            elif address==FREE:
                if (rcx,rdx)!=(b+0x6000,16):raise ValueError('Free fixture arguments changed')
                self.free_count+=1
            elif address==EXPIRED:
                if rcx!=self.owner:raise ValueError('Expired cleanup owner changed')
                self.expired_count+=1
            else:
                pointer=uc.reg_read(x.UC_X86_REG_R8);length=uc.reg_read(x.UC_X86_REG_R9)
                if (rcx,rdx)!=(b+0x5000,0x12345678) or pointer!=b+0x18000 or not 3<=length<=2048:
                    raise ValueError('Callback capture arguments changed')
                self.delivered.append(bytes(uc.mem_read(pointer,length)).hex())
            self.ret(uc);return
        if address==PROBE:self.probe_count+=1
        super().hook(uc,address,size,user)

    def execute_listener(self,stream,mode='live'):
        if len(stream)>2048 or mode not in ('live','none','expired'):raise ValueError('Fixture bound')
        uc=self.uc;b=self.scratch;self.owner=b+0x1000;pointer=b+0x18000
        self.copy_sizes=[];self.io_entries=[];self.delivered=[]
        self.snapshot_count=self.cleanup_count=self.free_count=self.expired_count=self.probe_count=0
        self.listener_count=0 if mode=='none' else 1
        uc.mem_write(self.owner,bytes(0x300))
        uc.mem_write(pointer,stream+b'\0')
        uc.mem_write(self.owner+0x198,struct.pack('<QQQ',pointer,pointer+len(stream)+1,pointer+4096))
        listener=b+0x4000;callback=b+0x5000;callback_table=b+0x5100
        uc.mem_write(listener,bytes(0x80))
        uc.mem_write(listener,struct.pack('<Q',self.table['table']))
        uc.mem_write(listener+0x18,struct.pack('<QQ',0x12345678,callback))
        uc.mem_write(callback,struct.pack('<Q',callback_table))
        uc.mem_write(callback_table,struct.pack('<QQ',0,self.capture_address))
        uc.mem_write(b+0x6100,struct.pack('<QQQQ',b+0x6200,0,0,0))
        uc.mem_write(b+0x6200,struct.pack('<QQ',listener,b+0x6300))
        uc.mem_write(b+0x6300,struct.pack('<QII',0,0 if mode=='expired' else 2,1))
        stack=b+0x30000;uc.mem_write(stack-512,bytes(1024))
        for reg,value in [(x.UC_X86_REG_RDI,self.owner),(x.UC_X86_REG_R15,0),(x.UC_X86_REG_RSP,stack)]:
            uc.reg_write(reg,value)
        uc.emu_start(START,END,count=100000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=END:raise ValueError('Listener loop budget exceeded')
        end=struct.unpack('<Q',bytes(uc.mem_read(self.owner+0x1a0,8)))[0]
        if not pointer+1<=end<=pointer+len(stream)+1:raise ValueError('Remaining range changed')
        refs=struct.unpack('<I',bytes(uc.mem_read(b+0x6308,4)))[0]
        if refs!=(0 if mode=='expired' else 2):raise ValueError('Native reference count unbalanced')
        if self.snapshot_count!=self.cleanup_count or self.snapshot_count!=self.free_count:
            raise ValueError('Fixture lifecycle unbalanced')
        return dict(stream_hex=stream.hex(),mode=mode,delivered=self.delivered.copy(),
                    remaining_hex=bytes(uc.mem_read(pointer,end-pointer-1)).hex(),
                    snapshots=self.snapshot_count,probes=self.probe_count,expired_cleanups=self.expired_count)


def wire_frame(payload):
    from vampir_core.frame_primitives import xor_transform
    return (len(payload)+3).to_bytes(3,'little')+xor_transform(payload)


def main():
    emulator=ListenerEmulator();cases=[]
    frames=[wire_frame(bytes(range(size))) for size in [2,3,8,16,64,255]]
    for frame in frames:
        for cut in sorted({0,1,2,3,4,len(frame)-1,len(frame)}):
            case=emulator.execute_listener(frame[:cut])
            if len(case['delivered'])!=(1 if cut==len(frame) else 0):raise ValueError('Partial delivery changed')
            if case['remaining_hex']!=(b'' if cut==len(frame) else frame[:cut]).hex():raise ValueError('Partial remainder changed')
            cases.append(case)
    stream=frames[0]+frames[2]+frames[4]+frames[5][:7]
    case=emulator.execute_listener(stream)
    if len(case['delivered'])!=3 or case['remaining_hex']!=frames[5][:7].hex():raise ValueError('Coalesced delivery changed')
    cases.append(case)
    for mode in ['none','expired']:
        case=emulator.execute_listener(frames[3],mode)
        if case['delivered'] or case['remaining_hex']!=frames[3].hex():raise ValueError('Absent listener consumed data')
        cases.append(case)
    for case in cases:
        for delivered in case['delivered']:
            output=bytes.fromhex(delivered)
            if output[3:]!=bytes(range(len(output)-3)):raise ValueError('Native XOR callback output differs')
    report=dict(schema_version=1,source=emulator.bindings['source'],sha256=emulator.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=emulator.listener_fragments,leaves=emulator.leaves,receive_table=emulator.table,
                cases=cases,statistics=dict(native_listener_cases=len(cases)),network_ready=False,
                limitations=['Native loop, virtual thunks, probe, broadcast helper, receive-A/XOR and compaction executed.',
                             'Snapshot/cleanup/free/expired-listener cleanup replaced by checked frozen-lifetime fixtures.',
                             'Final application callback captures bytes; actual Dispatch not executed.',
                             'One live/expired listener or none; multiple-listener lifetime mutation unverified.',
                             'No sockets, CRC integrity, receive-B replay or authorization proof.'])
    path=native.ROOT/'code-clues/headless-listener-loop.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(dict(output=str(path),**report['statistics'],network_ready=False)))


if __name__=='__main__':main()
