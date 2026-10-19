"""Native virtual40/state2 preparation, schedule boundary and deferred callback."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('state_selection_base',HERE/'replay-selection-service.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
START,STATE,CALLBACK=0x145dbba60,0x14560a400,0x145600690
READY,LABEL,PLAYER_READY,PLAYER_LOAD=0x30004000,0x30004010,0x30004020,0x30004030


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.state_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in
            (STATE,0x14560a6f0,0x145dc3f30,0x145609b00,0x14452afb0,CALLBACK,0x144328fe0)})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.state_fragments)
        self.state_leaves=[]
        a=0x1456048a0;off=self.image.offset(a-self.image.pe.base);data=self.raw[off:off+8]
        self.state_leaves.append(dict(address=a,file_offset=off,bytes=data.hex()));self.ranges.append((a,a+8))
        self.manager_global=a+7+struct.unpack_from('<i',data,3)[0]
        self.state_hooks={0x1444aacb0,0x1416aaaf0,0x14567d410,0x1454894b0,0x1454db7c0,0x1456140f0,
            0x145c5d860,0x141482990,0x141420cc0,0x14142d840,0x141424430,0x145670b80,
            0x1445cbd50,0x144a720c0,0x14141c190,0x1414313d0,0x143c15a20,0x1442b3a40,0x14143c260,
            READY,LABEL,PLAYER_READY,PLAYER_LOAD}
        rows=[r for f in self.state_fragments for r in f['instructions']]
        refs=[a for r in rows for a in r['rip_references']]
        pages={p for begin,end in self.ranges for p in range(begin & ~4095,(end+4095) & ~4095,4096)}
        pages.update(a & ~4095 for a in (*refs,*self.state_hooks,self.manager_global,0x14b520cc3,0x14b4f2060,0x148a9b730))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])
        self.ctx=0x22000000;self.uc.mem_map(self.ctx,0x10000)
        self.copy_sizes=[];self.io_entries=[]

    def fwrite(self,desc,text):
        data=text.encode('utf-16le')+b'\0\0' if text else b''
        pointer=self.alloc(len(data)) if data else 0
        if data:self.uc.mem_write(pointer,data)
        self.uc.mem_write(desc,struct.pack('<QII',pointer,len(data)//2,len(data)//2))

    def fread(self,desc):
        p,n,cap=struct.unpack('<QII',bytes(self.uc.mem_read(desc,16)))
        if not 0<=n<=cap<=256:raise ValueError('State fixture string bound')
        return bytes(self.uc.mem_read(p,(n-1)*2)).decode('utf-16le') if n else ''

    def hook(self,uc,address,size,user):
        if address not in self.state_hooks and address!=0x141421150:return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0;ctx=self.ctx
        if address==0x1444aacb0:result=ctx+0x1000
        elif address==0x1416aaaf0:self.events.append(dict(action='module_init_capture'))
        elif address==0x14567d410:self.events.append(dict(action='pre_state_helper_capture'))
        elif address==0x1454894b0:result=ctx+0x2000
        elif address==0x1454db7c0:self.events.append(dict(action='base_reset_helper_capture'))
        elif address==0x1456140f0:self.events.append(dict(action='state_diagnostic_capture',raw=b & 0xffffffff))
        elif address==0x145c5d860:
            uc.mem_write(a,bytes(16));self.events.append(dict(action='state_lookup_capture',raw=b & 0xffffffff))
        elif address==0x141482990:result=ctx+0x3000 if self.fixture['label_present'] else 0
        elif address==LABEL:result=ctx+0x3100
        elif address in (0x141420cc0,0x14143c260):
            text=self.fread(b);self.fwrite(a,text);result=a
            if address==0x14143c260:self.events.append(dict(action='load_label_copy_fixture',text=text))
        elif address in (0x14142d840,0x141421150):self.fwrite(a,'');result=a
        elif address==0x141424430:pass
        elif address==0x145670b80:
            # Conversion backend captured; exact label text copied as fixture.
            self.fwrite(a,self.fixture['label_text'] if self.fixture['label_present'] else '');result=a
        elif address==0x1445cbd50:result=ctx+0x4000 if self.fixture['ready_object'] else 0
        elif address==READY:
            result=self.fixture['ready'];self.events.append(dict(action='ready_virtual_capture',value=result))
        elif address==0x144a720c0:
            callback=int.from_bytes(uc.mem_read(a,8),'little')
            if callback!=CALLBACK:raise ValueError('Deferred state callback changed')
            self.queued=True
            self.events.append(dict(action='schedule_capture',callback=callback))
            # Leave descriptor alive so actual native cleanup path is also reached.
        elif address==0x14141c190:self.events.append(dict(action='delegate_cleanup_capture'))
        elif address==0x1414313d0:
            if b>256:raise ValueError('State FString allocation fixture')
            n=int.from_bytes(uc.mem_read(a+8,4),'little')
            uc.mem_write(a,struct.pack('<QII',self.alloc(max(2,b*2)),n,b))
        elif address==0x143c15a20:result=ctx+0x5000
        elif address==0x1442b3a40:result=ctx+0x7000
        elif address==PLAYER_READY:result=int(self.fixture['player_ready'])
        elif address==PLAYER_LOAD:self.events.append(dict(action='player_load_virtual_capture',text=self.fread(b),raw=c & 255))
        else:raise ValueError('Unknown state fixture '+hex(address))
        self.finish(result)

    def setup(self,fixture):
        self.initialize();self.fixture=fixture;self.events=[];self.queued=False
        ctx=self.ctx;self.uc.mem_write(ctx,bytes(0x10000))
        self.uc.mem_write(self.manager_global,struct.pack('<Q',ctx+0x8000 if fixture['manager_present'] else 0))
        self.uc.mem_write(ctx+0x8038,struct.pack('<Q',ctx+0x1000 if fixture['auth_present'] else 0))
        self.uc.mem_write(ctx+0x1110,struct.pack('<Q',ctx+0x9000 if fixture['module_present'] else 0))
        self.uc.mem_write(ctx+0x9400,bytes([fixture['auth_ready']]))
        self.uc.mem_write(0x14b520cc3,bytes([fixture['sdk_enabled']]))
        self.uc.mem_write(0x14b4f2060,b'\0')
        self.uc.mem_write(ctx+0x3000,struct.pack('<Q',ctx+0xa000))
        self.uc.mem_write(ctx+0xa020,struct.pack('<Q',LABEL))
        self.fwrite(ctx+0x3100,fixture['label_text'])
        self.uc.mem_write(ctx+0x4000,struct.pack('<Q',ctx+0xb000))
        self.uc.mem_write(ctx+0xb7b8,struct.pack('<Q',READY))
        self.uc.mem_write(self.service+0x40,struct.pack('<II',7,9))
        self.uc.mem_write(self.service+0xc1,b'\0')

    def execute(self,fixture):
        self.setup(fixture)
        self.run(START,self.service)
        return dict(fixture=fixture,events=self.events.copy(),queued=self.queued,
            state=list(struct.unpack('<II',bytes(self.uc.mem_read(self.service+0x40,8)))),
            pending=int.from_bytes(self.uc.mem_read(self.service+0xc1,1),'little'))

    def callback_case(self,fixture):
        self.setup(fixture);ctx=self.ctx
        self.uc.mem_write(ctx+0x5158,struct.pack('<Q',ctx+0x6000 if fixture['player_present'] else 0))
        self.uc.mem_write(ctx+0x6000,struct.pack('<Q',ctx+0xc000))
        self.uc.mem_write(ctx+0xc7f8,struct.pack('<Q',PLAYER_READY))
        self.uc.mem_write(ctx+0xc800,struct.pack('<Q',PLAYER_LOAD))
        self.uc.mem_write(ctx+0x5740,struct.pack('<I',fixture['phase']))
        self.uc.mem_write(ctx+0x5718,struct.pack('<I',0xabcdef))
        self.uc.mem_write(ctx+0x5731,b'\x7f')
        self.uc.mem_write(ctx+0x7080,bytes([fixture['busy']]))
        self.fwrite(ctx+0xd000,'callback-label-fixture')
        returned=self.run(CALLBACK,ctx+0xd000) & 255
        return dict(fixture=fixture,events=self.events.copy(),returned=returned,
            flag731=int.from_bytes(self.uc.mem_read(ctx+0x5731,1),'little'),
            field718=int.from_bytes(self.uc.mem_read(ctx+0x5718,4),'little'))


def build():
    path=native.ROOT/'code-clues/selection-service-replay.json';prior=json.loads(path.read_text('utf-8'))
    em=Emulator()
    if prior['sha256']!=em.bindings['sha256']:raise ValueError('Selection state source changed')
    default=dict(sdk_enabled=False,manager_present=True,auth_present=True,module_present=True,auth_ready=1,
        ready_object=True,ready=1,label_present=True,label_text='state-label-fixture')
    cases=[]
    for ready in (0,1):
        for label in (False,True):cases.append(em.execute(dict(default,name=f'ready-{ready}-label-{label}',ready=ready,label_present=label)))
    for update in (dict(name='sdk-reject',sdk_enabled=True,auth_ready=0),dict(name='sdk-accept',sdk_enabled=True),
        dict(name='no-manager',sdk_enabled=True,manager_present=False),dict(name='no-auth',sdk_enabled=True,auth_present=False),
        dict(name='no-module',sdk_enabled=True,module_present=False),dict(name='no-ready-object',ready_object=False)):
        cases.append(em.execute(dict(default,**update)))
    callbacks=[]
    for player in (False,True):
        for ready in (False,True):
            for phase,busy in ((0,False),(2,False),(0,True)):
                fixture=dict(default,player_present=player,player_ready=ready,phase=phase,busy=busy)
                callbacks.append(em.callback_case(fixture))
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fragments=em.state_fragments,leaves=em.state_leaves,cases=cases,callbacks=callbacks,native_execution=True,network_ready=False,
        limitations=['Actual virtual40/base-reset/state-label/SetState/auth guard execute until schedule boundary, native cleanup executes.',
            'SDK cache getter, objects/ready virtual/lookup/text conversion/allocator/diagnostics/scheduler backends fixtures.',
            'Deferred callback runs separately with synthetic world/player objects, not automatically by real scheduler.',
            'No slot90 call observed on covered paths; lifecycle after requested world load remains unknown.',
            'No network/frame/socket/server/character list response/game launch/profile/process memory/credentials/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/selection-state-transition-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']),callbacks=len(report['callbacks']))))
