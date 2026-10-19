"""Execute selection lifecycle event entrypoints with explicit backend captures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('lifecycle_base',HERE/'replay-selection-service.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
WORLD_EVENT,DISPATCH,CALLBACK=0x14561b000,0x145619e40,0x1455f7bb0
EXIT_CAPTURE=0x30006000


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(WORLD_EVENT)]})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.fragments)
        off=self.image.offset(CALLBACK-self.image.pe.base)
        data=self.raw[off:off+16]
        if data[:3]!=b'\x48\x8b\x0d' or data[7:]!=bytes.fromhex('33d2488b0148ff6038'):
            raise ValueError('Lifecycle callback leaf changed: '+data.hex())
        self.leaf=dict(address=CALLBACK,file_offset=off,bytes=data.hex())
        self.callback_global=CALLBACK+7+struct.unpack_from('<i',data,3)[0]
        self.ranges.append((CALLBACK,CALLBACK+16))
        self.lifecycle_hooks={DISPATCH,0x144a64cc0,EXIT_CAPTURE}
        refs=[a for f in self.fragments for r in f['instructions'] for a in r['rip_references']]
        pages={p for lo,hi in self.ranges for p in range(lo & ~4095,(hi+4095)&~4095,4096)}
        pages.update(a & ~4095 for a in (*refs,*self.lifecycle_hooks,self.callback_global))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])

    def hook(self,uc,address,size,user):
        if address not in self.lifecycle_hooks:return super().hook(uc,address,size,user)
        a,b,c=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        if address==DISPATCH:
            self.events.append(dict(action='state_dispatch_capture',this_is_service=a==self.service,raw=b & 0xffffffff))
        elif address==0x144a64cc0:
            self.events.append(dict(action='delegate_broadcast_capture',this_offset=a-self.service,
                descriptor=int.from_bytes(uc.mem_read(b,8),'little'),raw=int.from_bytes(uc.mem_read(c,4),'little')))
        else:self.events.append(dict(action='virtual38_capture',this_is_service=a==self.service,raw=b))
        self.finish(0)

    def event_case(self,raw):
        self.initialize();self.events=[]
        self.run(WORLD_EVENT,self.service,raw)
        return dict(raw=raw,state40=int.from_bytes(self.uc.mem_read(self.service+0x40,4),'little'),events=self.events.copy())

    def callback_case(self):
        self.initialize();self.events=[]
        # Synthetic backend table deliberately captures slot38; actual leaf reads actual global.
        table=self.scratch+0xe000
        self.uc.mem_write(self.callback_global,struct.pack('<Q',self.service))
        self.uc.mem_write(self.service,struct.pack('<Q',table))
        self.uc.mem_write(table+0x38,struct.pack('<Q',EXIT_CAPTURE))
        self.run(CALLBACK)
        return dict(events=self.events.copy())


def build():
    em=Emulator()
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),fragments=em.fragments,
        leaf=em.leaf,callback_global=em.callback_global,
        events=[em.event_case(v) for v in (0,1,2,18,0x7fffffff,0x80000000,0xffffffff)],
        callback=em.callback_case(),native_execution=True,network_ready=False,
        limitations=['Actual world-event entrypoint writes state40, reaches state-dispatch then delegate-broadcast captures.',
            'Dispatcher body, event emitter, registration, real level loading and delegate implementation are not executed.',
            'Actual 16-byte callback reads singleton global and tail-jumps slot38 with raw0; synthetic table captures target.',
            'No proven slot90 caller, network, server timing, game launch, live session, profile or Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/selection-lifecycle-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['events'])+1)))
