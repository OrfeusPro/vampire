"""Execute actual CharacterSelect writer and archive IO against selection snapshots."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('select_writer_base',HERE/'replay-version-packet-writer.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
WRITER=0x1456e53a0


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.select_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(WRITER)]})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.select_fragments)
        for lo,hi in self.ranges:
            for page in range(lo & ~4095,(hi+4095)&~4095,4096):
                if any(a<=page<=b for a,b,_ in self.uc.mem_regions()):continue
                self.uc.mem_map(page,4096);off=self.image.offset(page-self.image.pe.base)
                self.uc.mem_write(page,self.raw[off:off+4096])

    def write(self,values):
        self.heap=self.scratch+0x10000;self.copy_sizes=[];self.io_entries=[]
        packet,archive,buffer=self.scratch+0x1000,self.scratch+0x2000,self.scratch+0x8000
        self.uc.mem_write(packet,bytes(0x30))
        for o,fmt,v in zip((0x10,0x18,0x20),('<Q','<I','<Q'),values):
            self.uc.mem_write(packet+o,struct.pack(fmt,v))
        self.call(0x144aa62f0,archive,1)
        self.uc.mem_write(archive+0x18,struct.pack('<QQQ',buffer,buffer,buffer+256))
        self.uc.mem_write(archive+0x30,struct.pack('<III',256,0,0))
        result=self.call(WRITER,packet,archive)
        size=int.from_bytes(self.uc.mem_read(archive+0x34,4),'little')
        return dict(values=list(values),returned=result,payload_hex=bytes(self.uc.mem_read(buffer,size)).hex())


def build():
    em=Emulator();prior_path=native.ROOT/'code-clues/selection-service-replay.json'
    prior=json.loads(prior_path.read_text('utf-8'))
    if prior['sha256']!=em.bindings['sha256']:raise ValueError('Select source mismatch')
    values=[(c['raw64'],c['raw32'],c['state_raw_f0']) for c in prior['cases']]
    values.extend((a,b,c) for a in (0,1,2**64-1) for b in (0,2**32-1) for c in (0,2**64-1))
    cases=[em.write(v) for v in values]
    if any(not c['returned'] or c['payload_hex']!=struct.pack('<QIQ',*c['values']).hex() for c in cases):
        raise ValueError('Native select encoding mismatch')
    binding=next(p for p in em.bindings['packets'] if p['name']=='PktCharacterSelect')
    if binding['writer']!=WRITER or binding['packet_id']!=109:raise ValueError('Select binding mismatch')
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
        fragments=em.select_fragments,packet_binding=binding,cases=cases,native_execution=True,network_ready=False,
        limitations=['Actual packet writer and scalar archive IO execute, CRT memcpy bounded shim.',
            'Independent writer consumes prior actual selection handoff snapshots, not whole selection-to-frame execution.',
            'Raw object offsets10/18/20; identifier semantics and real account inputs not inferred.',
            'No frame/socket/response110/session/position/game process/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-select-writer-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
