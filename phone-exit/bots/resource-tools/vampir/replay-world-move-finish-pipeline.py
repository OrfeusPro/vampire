"""ID110 then actual ID206 body reader/handler in one emulator, no network."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,HERE/filename)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


world=module('world_pipeline_handler','replay-world-move-finish.py')
reader=module('world_pipeline_reader','replay-world-move-finish-collections.py')
native,x=world.native,world.x


class Emulator(world.Emulator):
    def __init__(self):
        self.defer_handler=False;self.reading_world=False
        super().__init__()
        support=reader.Emulator()
        self.reader_ranges=support.world_ranges+support.support_ranges
        self.reader_leaves=support.world_leaves
        self.ranges.extend(support.ranges)
        for lo,hi in support.ranges:
            for page in range(lo & ~4095,(hi+4095)&~4095,4096):self.map_source_page(page)
        self.collection_allocators.update({0x14167f710:0x78,0x14167f160:0x78})
        self.collection_cleanup.add(0x145770460)
        for a in (0x14167f710,0x14167f160,0x145770460,0x1456b8980,0x145679730):self.map_source_page(a & ~4095)

    def hook(self,uc,address,size,user):
        if self.defer_handler and address==world.HANDLER:
            # Dispatch boundary: leave the ID110 state intact and prepare an
            # actual decoded ID206 packet before entering its handler.
            self.defer_handler=False;uc.reg_write(x.UC_X86_REG_RIP,self.scratch+0x3f000);uc.emu_stop();return
        if self.reading_world and address==0x1456b8980:
            if uc.reg_read(x.UC_X86_REG_RDX):raise ValueError('Fresh world cleanup required')
            self.finish(uc.reg_read(x.UC_X86_REG_RAX));return
        if self.handler_phase and address==0x145679730:
            self.events.append(dict(action='world_item_capture',enum=uc.reg_read(x.UC_X86_REG_RDX) & 255,
                raw10=uc.reg_read(x.UC_X86_REG_R8),raw_c=uc.reg_read(x.UC_X86_REG_R9D)))
            self.finish(0);return
        return super().hook(uc,address,size,user)

    def execute_pipeline(self,body,gate_state=0):
        self.defer_handler=True
        # Reuse the existing selected-player, service and initialized TLS setup.
        # Its synthetic ID206 object never enters the handler.
        self.execute_world(0,gate_state,0,0,0)
        self.handler_phase=False;self.reading_world=True
        decoded=reader.base.Emulator.read_world(self,body)
        self.reading_world=False
        if decoded['returned']!=1:raise ValueError('Complete world body required')
        self.handler_phase=True;self.events=[];self.gate_return=None
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000;self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,self.context),
            (x.UC_X86_REG_RDX,0x12345678),(x.UC_X86_REG_R8,self.scratch+0x1000)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(world.HANDLER,stop,count=500000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('World pipeline budget')
        return dict(decoded=decoded,gate_state=gate_state,events=self.events.copy(),state=dict(
            status30=self.uc.mem_read(self.context+0x5030,1)[0],
            raw40=int.from_bytes(self.uc.mem_read(self.context+0x5040,4),'little'),
            player1f8=int.from_bytes(self.uc.mem_read(self.context+0x11f8,4),'little'),
            refs=int.from_bytes(self.uc.mem_read(self.context+0x2008,4),'little')))


def build():
    em=Emulator();cases=[]
    for code in (0,1,0x1197):
        for gate in (0,1):
            c=em.execute_pipeline(reader.base.body_bytes(code=code),gate);cases.append(c)
    arrays={'appearance':((1,255,2),),'b8':((3,4),),
        'c8':((5,6,7,8,9,10,11,12,13,14,255,1.5,-2.25,-0.,255),),
        'e8':((255,17,18,19,255,1.5,-2.25,-0.,45),),'100':(20,21)}
    cases.append(em.execute_pipeline(reader.body_bytes(arrays,'Ж界🙂')))
    for case in cases:
        code=case['decoded']['fields']['0x10'];accepted=code==0 or (code==0x1197 and case['gate_state']==0)
        if case['state']['status30']!=(6 if accepted else 1) or case['state']['refs']!=2:
            raise ValueError('Whole reader/handler transition mismatch')
        if accepted and (case['state']['raw40'],case['state']['player1f8'])!=(0xffffffff,0xffffffff):
            raise ValueError('Decoded field not applied')
    if [e for e in cases[-1]['events'] if e['action']=='world_item_capture']!=[dict(action='world_item_capture',enum=5,raw10=18,raw_c=17)]:
        raise ValueError('Nonempty world item handoff mismatch')
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-world-move-finish.py','replay-world-move-finish-reader.py','replay-world-move-finish-collections.py')},
        reader_ranges=em.reader_ranges,reader_leaves=em.reader_leaves,cases=cases,native_execution=True,network_ready=False,
        limitations=['ID110 initialization and actual ID206 constructor/reader/handler/service/lifecycle/status execute in one emulator.',
            'Dispatch invocation is synthetic; packet arrival and trigger after selection not proved. No socket IO.',
            'Bounded storage and external actor/world/UI/SDK/diagnostic boundaries inherited from documented reader and handler scenarios.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/world-move-finish-pipeline-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
