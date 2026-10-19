"""WaitingEnd -> selection/list branch -> actual packet/wrapper/frame/queue."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('select_send_base',HERE/'replay-login-send-path.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
WAIT,QUICK,PREDICATE,SELECT=0x146768540,0x145d46400,0x145c85d90,0x145dc05f0
SERVICE_TABLE=0x1499f11f0
STORED,STATE_GETTER,RECORD_LOOKUP=0x145d43290,0x145c859f0,0x145c847c0
POLICY=0x3000a000


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.select_binding=next(p for p in self.bindings['packets'] if p['name']=='PktCharacterSelect')
        self.list_binding=next(p for p in self.bindings['packets'] if p['name']=='PktCharacterListRead')
        addresses=(WAIT,QUICK,PREDICATE,SELECT,STORED,0x145dbfe50,self.select_binding['writer'],
            self.select_binding['name_getter'],self.list_binding['name_getter'])
        self.select_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in addresses})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.select_fragments)
        self.select_leaves=[]
        for a,size in ((0x1456048e0,8),(STATE_GETTER,8),(RECORD_LOOKUP,34),(0x144aaaab0,12),(0x1456d54d0,22),
                (self.select_binding['constructor'],30),(self.select_binding['id_getter'],6),
                (self.list_binding['constructor'],18),(self.list_binding['id_getter'],6),(self.list_binding['writer'],3)):
            off=self.image.offset(a-self.image.pe.base)
            self.select_leaves.append(dict(address=a,file_offset=off,bytes=self.raw[off:off+size].hex()))
            self.ranges.append((a,a+size))
        off=self.image.offset(STATE_GETTER-self.image.pe.base);getter=self.raw[off:off+8]
        if getter[:3]!=b'\x48\x8b\x05' or getter[-1]!=0xc3:raise ValueError('State getter changed')
        self.state_global=STATE_GETTER+7+struct.unpack_from('<i',getter,3)[0]
        self.select_hooks={0x145610ab0,0x144aa7c40,0x1456b2340,0x14560dd00,
            0x145c8b1b0,0x144a21450,0x1463fc200,0x144a20390,0x145d37220,0x1445cbd50,
            0x1454f2ba0,0x145dbba60,0x141421150,0x1413fe190,0x1445cc260,0x145c76830,POLICY}
        rows=[r for f in self.select_fragments for r in f['instructions']]
        refs=[a for r in rows for a in r['rip_references']]
        pages={p for lo,hi in self.ranges for p in range(lo & ~4095,(hi+4095)&~4095,4096)}
        pages.update(a & ~4095 for a in (*refs,*self.select_hooks,SERVICE_TABLE,
            self.select_binding['vtable'],self.list_binding['vtable'],0x14b574a90,0x14b27eecb,self.state_global))
        pages.update((a & ~4095)+4096 for a in self.select_hooks if a>0x140000000)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])
        self.ctx=0x22000000;self.uc.mem_map(self.ctx,0x10000)
        self.service=self.ctx+0x5000

    def hook(self,uc,address,size,user):
        if address in (WAIT,QUICK,PREDICATE,SELECT,STORED,RECORD_LOOKUP,self.select_binding['writer'],self.list_binding['writer']):
            self.events.append(dict(action='native_entry',address=address))
        if address==base.HANDOFF:
            packet=uc.reg_read(x.UC_X86_REG_RDX)
            self.events.append(dict(action='select_handoff',kind=uc.reg_read(x.UC_X86_REG_R8)&65535,
                packet_raw10=int.from_bytes(uc.mem_read(packet+0x10,8),'little'),
                packet_raw18=int.from_bytes(uc.mem_read(packet+0x18,4),'little'),
                packet_raw20=int.from_bytes(uc.mem_read(packet+0x20,8),'little')))
        if address==0x141420f70:
            a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
            name=bytearray()
            for i in range(64):
                c=bytes(uc.mem_read(b+i,1))
                if c==b'\0':break
                name.extend(c)
            else:raise ValueError('Select packet name bound')
            if name not in (b'PktCharacterSelect',b'PktCharacterListRead'):raise ValueError('Unexpected select-path string')
            payload=name.decode('ascii').encode('utf-16le')+b'\0\0';p=self.alloc(len(payload));uc.mem_write(p,payload)
            uc.mem_write(a,struct.pack('<QII',p,len(payload)//2,len(payload)//2))
            self.events.append(dict(action='packet_name_constructor_fixture',name=name.decode('ascii')))
            self.finish_fixture(a);return
        if address not in self.select_hooks:return super().hook(uc,address,size,user)
        a,b,c=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        result=0;ctx=self.ctx
        if address==0x145610ab0:
            if a!=self.service:raise ValueError('Select service receiver changed')
            self.events.append(dict(action='base_selection_capture',raw64=b,raw32=c & 0xffffffff))
        elif address==0x144aa7c40:result=self.manager
        elif address==0x1456b2340:self.events.append(dict(action='packet_cleanup_capture'))
        elif address==0x14560dd00:self.events.append(dict(action='list_preparation_capture'))
        elif address==0x145c8b1b0:self.events.append(dict(action='state_toggle_capture',value=b & 255))
        elif address==0x144a21450:result=ctx+0x7000
        elif address==0x1463fc200:result=ctx+0x7100
        elif address==0x144a20390:result=0
        elif address==0x145d37220:result=ctx+0x4000
        elif address==0x1445cbd50:result=ctx+0x8000 if self.fixture['policy_present'] else 0
        elif address==0x1454f2ba0:result=ctx+0xa000
        elif address==0x1445cc260:result=ctx+0x8000 if self.fixture.get('ui_present',True) else 0
        elif address==0x145c76830:result=ctx+0xa000
        elif address==0x145dbba60:self.events.append(dict(action='selection_virtual40_capture'))
        elif address==0x141421150:uc.mem_write(a,bytes(16));result=a
        elif address==0x1413fe190:pass
        elif address==POLICY:
            if a!=ctx+0x8000:raise ValueError('Policy receiver changed')
            result=self.fixture['policy'];self.events.append(dict(action='policy_virtual_capture',value=result))
        self.finish_fixture(result)

    def execute(self,fixture,entry=WAIT):
        self.fixture=fixture;self.events=[];self.heap=self.scratch+0x10000
        self.copy_sizes=[];self.io_entries=[];self.queue_calls=self.wake_calls=0
        b=self.scratch;wrapper,peer,queue=b+0x3000,b+0x4000,b+0xa000
        self.manager=b+0xb000
        self.uc.mem_write(wrapper,struct.pack('<Q',base.HANDLE_TABLE))
        self.uc.mem_write(wrapper+0x10,struct.pack('<Q',peer));self.uc.mem_write(base.GLOBAL,struct.pack('<Q',wrapper))
        self.uc.mem_write(peer,bytes(0x400));self.uc.mem_write(peer+0x108,struct.pack('<I',1))
        self.uc.mem_write(peer+0xc0,struct.pack('<I',int(not fixture['wake'])))
        self.uc.mem_write(peer+0x50,struct.pack('<Q',b+0x6000));self.uc.mem_write(b+0x6020,struct.pack('<Q',self.wake_address))
        self.uc.mem_write(peer+0x240,struct.pack('<H',fixture['sequence']));self.uc.mem_write(peer+0x248,struct.pack('<Q',fixture['key']))
        self.uc.mem_write(peer+0x2a5,bytes([fixture['special']]));self.uc.mem_write(peer+0x2a6,bytes([fixture['peer_flag']]))
        self.uc.mem_write(base.base.DISABLE,bytes([fixture['disabled']]))
        self.uc.mem_write(base.base.FILTER,struct.pack('<Q',b+0xe000));self.uc.mem_write(b+0xe000,bytes(8))
        self.metadata=b+0xf000;self.uc.mem_write(self.metadata+0x18,bytes([fixture['metadata_byte']]))
        self.uc.mem_write(peer+0x178,struct.pack('<QQQ',queue,queue+1,queue+4096));self.uc.mem_write(queue,bytes(4096))
        self.uc.mem_write(self.manager,bytes(0x100));self.uc.mem_write(self.manager+0x30,struct.pack('<f',fixture['default_timeout']))
        nodes,buckets=b+0xc000,b+0xd000;self.uc.mem_write(nodes,bytes(0x100));self.uc.mem_write(buckets,b'\xff'*64)
        self.uc.mem_write(self.manager+0x38,struct.pack('<Q',nodes));self.uc.mem_write(self.manager+0x40,struct.pack('<I',len(fixture['pending_kinds'])))
        self.uc.mem_write(self.manager+0x80,struct.pack('<I',4));self.uc.mem_write(self.manager+0x78,struct.pack('<Q',buckets))
        if fixture['pending_kinds']:self.uc.mem_write(buckets+4*(110 & 3),struct.pack('<i',0))
        for index,kind in enumerate(fixture['pending_kinds']):
            self.uc.mem_write(nodes+index*0x20,struct.pack('<H',kind))
            self.uc.mem_write(nodes+index*0x20+0x18,struct.pack('<i',index+1 if index+1<len(fixture['pending_kinds']) else -1))
        ctx=self.ctx;self.uc.mem_write(ctx,bytes(0x10000))
        self.uc.mem_write(self.service,struct.pack('<Q',SERVICE_TABLE));self.uc.mem_write(0x14b574a90,struct.pack('<Q',self.service))
        self.uc.mem_write(ctx+0x10f0,struct.pack('<Q',fixture['state_f0']))
        self.uc.mem_write(self.state_global,struct.pack('<Q',ctx+0x1000))
        self.uc.mem_write(ctx+0x4028,struct.pack('<Q',fixture['stored_raw']))
        self.uc.mem_write(0x14b27eecb,bytes([fixture['policy_disabled']]))
        self.uc.mem_write(ctx+0x8000,struct.pack('<Q',ctx+0x9000));self.uc.mem_write(ctx+0x8010,struct.pack('<Q',ctx+0xa200))
        self.uc.mem_write(ctx+0xa230,struct.pack('<Q',ctx+0xa400));self.uc.mem_write(ctx+0xa238,struct.pack('<i',1))
        self.uc.mem_write(ctx+0xa038,struct.pack('<i',1));self.uc.mem_write(ctx+0xa408,struct.pack('<Q',ctx+0xa030))
        self.uc.mem_write(ctx+0x9a18,struct.pack('<Q',POLICY))
        if entry==STORED:
            self.uc.mem_write(ctx+0xa238,struct.pack('<i',fixture.get('type_count',1)))
            self.uc.mem_write(ctx+0xa408,struct.pack('<Q',ctx+0xa030 if fixture.get('type_match',True) else 0))
            self.uc.mem_write(ctx+0x83f8,struct.pack('<i',fixture['selected_index']))
            records=fixture['record_keys'];record_pointer=ctx+0xc000
            if len(records)>4:raise ValueError('Stored record fixture bound')
            self.uc.mem_write(ctx+0x1070,struct.pack('<QII',record_pointer,len(records),len(records)))
            for index,key in enumerate(records):self.uc.mem_write(record_pointer+index*0x170+8,struct.pack('<Q',key))
        notify=b+0x2000;self.call(0x1456d54d0,notify)
        self.uc.mem_write(notify+0x10,struct.pack('<Q',fixture['notify_raw']))
        stack,stop=b+0x30000,b+0x3f000;self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,ctx),(x.UC_X86_REG_RDX,0x12345678),(x.UC_X86_REG_R8,notify)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(entry,stop,count=250000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('Whole selection send budget')
        end=int.from_bytes(self.uc.mem_read(peer+0x180,8),'little')
        if not queue+1<=end<=queue+4096:raise ValueError('Select queue bound')
        frame=bytes(self.uc.mem_read(queue,end-queue-1))
        self.uc.mem_write(b+0x9000,b'\xcc'*4096)
        if frame!=bytes(self.uc.mem_read(queue,len(frame))):raise ValueError('Select queue borrowed temporary archive')
        return dict(fixture=fixture,entry=entry,events=self.events.copy(),frame_hex=frame.hex(),queue_calls=self.queue_calls,
            wake_calls=self.wake_calls,sequence_after=int.from_bytes(self.uc.mem_read(peer+0x240,2),'little'),queue_owns_bytes=True)


def build():
    em=Emulator();default=dict(peer_flag=0,policy_disabled=False,policy_present=True,policy=0,
        notify_raw=0x0102030405060708,stored_raw=0x8877665544332211,state_f0=0x123456789abcdef,
        sequence=0,key=0,wake=False,metadata_present=False,metadata_byte=7,disabled=False,raw_mode=0,special=False,
        default_timeout=12.5,pending_kinds=[])
    cases=[]
    for peer in (0,1):
        for policy in (0,1,2,4):
            for stored in (0,0x8877665544332211):
                cases.append(em.execute(dict(default,name=f'peer{peer}-policy{policy}-stored{int(bool(stored))}',
                    peer_flag=peer,policy=policy,stored_raw=stored)))
    for update in (dict(name='keyed-wrap',sequence=65535,key=0x1020304050607080,wake=True,metadata_present=True),
            dict(name='duplicate',pending_kinds=[110]),dict(name='duplicate-collision',pending_kinds=[102,106,110]),
            dict(name='collision-only',pending_kinds=[102,106]),dict(name='disabled',disabled=True),
            dict(name='mode2',raw_mode=2),dict(name='special',special=True),dict(name='policy-disabled',policy_disabled=True),
            dict(name='policy-absent',policy_present=False),dict(name='zero-state',state_f0=0),dict(name='max-state',state_f0=2**64-1)):
        cases.append(em.execute(dict(default,**update)))
    state_path=native.ROOT/'code-clues/character-state-f0-replay.json'
    state_report=json.loads(state_path.read_text('utf-8'))
    if state_report['sha256']!=em.bindings['sha256']:raise ValueError('Select state evidence source mismatch')
    state_case=next(c for c in state_report['cases'] if c['fixture']['name']=='count-3-preferred-22')
    stored_default=dict(default,record_keys=state_case['state']['record_raw8'],selected_index=1,
        state_f0=state_case['state_raw_f0'])
    stored_cases=[]
    for keys in ([],[11],[11,22,33],[11,22,22,33],[0,2**64-1]):
        for index in (-1,0,1,len(keys),2**31-1):
            stored_cases.append(em.execute(dict(stored_default,name=f'index{index}-count{len(keys)}',
                record_keys=keys,selected_index=index),entry=STORED))
    for update in (dict(name='ui-absent',ui_present=False),dict(name='type-count-zero',type_count=0),
            dict(name='type-mismatch',type_match=False),dict(name='ui-global-disabled',policy_disabled=True),
            dict(name='ui-duplicate',pending_kinds=[110]),dict(name='ui-disabled',disabled=True),
            dict(name='ui-mode2',raw_mode=2),dict(name='ui-special',special=True),
            dict(name='ui-keyed-wrap',sequence=65535,key=0x1020304050607080,wake=True,metadata_present=True)):
        stored_cases.append(em.execute(dict(stored_default,**update),entry=STORED))
    anchors=[]
    for address,size in ((SERVICE_TABLE,0x98),(0x14961a378,8),(0x14961a380,4),
            (em.select_binding['vtable'],0x40),(em.list_binding['vtable'],0x40)):
        off=em.image.offset(address-em.image.pe.base);anchors.append(dict(address=address,file_offset=off,bytes=em.raw[off:off+size].hex()))
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-login-send-path.py','replay-version-send-path.py','replay-selection-service.py')},
        fragments=em.select_fragments+em.login_fragments+em.extra+em.send_fragments,
        leaves=em.select_leaves,anchors=anchors,state_global=em.state_global,cases=cases,stored_cases=stored_cases,
        state_evidence_sha256=hashlib.sha256(state_path.read_bytes()).hexdigest(),native_execution=True,network_ready=False,
        limitations=['Actual WaitingEnd handler/predicate/quick helper/service virtual50/packet constructors/handoff/wrapper/scalar writer/frame/owning queue execute.',
            'Policy/type metadata, stored selection, state_f0, notify body and transport/queue/request-manager objects are synthetic fixtures.',
            'Insert/notify, metadata/name/allocator/cleanup/wake and UI/base selection helpers are captures; virtual40 continuation is captured.',
            'Stored caller executes actual signed index lookup over synthetic state records; rawF0 snapshot comes from prior native ID102 handler, not the same body-to-send run.',
            'No proven server notify lifecycle, engine/UI event emitter or field semantic names; no actual request timeout lifecycle, drain/socket/ID110/session/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-select-send-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
