"""Whole ID110 reader -> actual gate/handler/player apply, backend captures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('select_handler_base',HERE/'replay-character-select-fields.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.base.x
HANDLER,GATE,ACQUIRE,APPLY=0x14675e9a0,0x1467a8e10,0x145c8ba50,0x145d61e60
EXIT,TEXT,METADATA,CLASS,REFRESH=0x3000f000,0x3000f010,0x3000f020,0x3000f030,0x3000f040
RESET=0x3000b000


class Emulator(base.Emulator):
    def __init__(self):
        self.handler_phase=False
        super().__init__()
        manifest=json.loads((native.ROOT/'ghidra/entry-manifest.json').read_text('utf-8'))
        self.handler_ranges=[]
        for function in manifest['functions']:
            if function['name'] not in ('CharacterSelectResult_Handler','Result_Gate','SelectResult_PlayerAcquire'):continue
            for r in function['ranges']:
                lo,hi=int(r['start'],16),int(r['end_exclusive'],16)
                if hashlib.sha256(self.raw[r['file_offset']:r['file_offset']+hi-lo]).hexdigest()!=r['sha256']:
                    raise ValueError('Handler source range changed')
                self.handler_ranges.append(r);self.ranges.append((lo,hi))
        self.handler_leaves=[]
        off=self.image.offset(0x1498d8a80+0x28-self.image.pe.base)
        getter=struct.unpack_from('<Q',self.raw,off)[0]
        for address,size in ((getter,6),(0x1456048e0,8)):
            offset=self.image.offset(address-self.image.pe.base);data=self.raw[offset:offset+size]
            if address==getter and data!=bytes.fromhex('b86e000000c3'):raise ValueError('ID110 getter changed')
            self.handler_leaves.append(dict(address=address,file_offset=offset,bytes=data.hex()))
            self.ranges.append((address,address+size))
        self.getters={0x14558edf0:0x4000,0x145c859f0:0x8000,0x145cdf220:0x9000,
            0x145d04470:0x9000,0x144a21450:0x9000,0x145cb2f70:0x9000,0x14558ee30:0x9000,
            0x1455b8180:0x9000,0x1455e1510:0x9000,0x1455b8260:0x6000,0x145d044b0:0x9000,
            0x14558ee60:0xa000,0x1456048b0:0x9000,0x14563d9a0:0x9000,0x1456048a0:0xb000,
            0x1455b8270:0x9000,0x1455b81a0:0x7000,0x1445c6860:0x9000,0x14217cdb0:0x9000,
            0x14558ee40:0x3000}
        self.actions={0x145ceb7e0,0x145ced600,0x145d15460,0x145cc4130,0x1455960a0,0x145d3db30,
            0x145d3dfc0,0x145d6d710,0x145d74b40,0x145d17ed0,0x145dea660,0x145596150,
            0x14558d3f0,0x145d6cc70,0x145d799c0,0x145d179f0,0x1456140f0,0x14564e820,
            0x14567b7a0,0x1463e6e90,0x1463df2a0,0x144a24f80,0x144a4af10,0x145c8b6b0}
        self.handler_hooks=set(self.getters)|self.actions|{0x14142d840,0x141424430,0x14147d580,
            0x141421150,0x1413fe190,0x141420f70,0x145f8a7a0,0x14143c260,0x1458819c0,0x141482990,
            0x145d7bce0,0x145d7bf90,0x145d7db30,0x141876600,0x1417f24d0,0x1463cca20,
            0x1463dfb20,0x144a1cbf0,0x1445c83c0,EXIT,TEXT,METADATA,CLASS,RESET,REFRESH}
        self.gate_return=None
        for lo,hi in self.ranges:
            for page in range(lo & ~4095,(hi+4095)&~4095,4096):self.map_source_page(page)
        for a in (*self.handler_hooks,0x14b574a90,0x14b520cc3):
            self.map_source_page(a & ~4095);self.map_source_page((a & ~4095)+4096)
        self.context=0x23000000;self.uc.mem_map(self.context,0x20000)

    def hook(self,uc,address,size,user):
        if not self.handler_phase:return super().hook(uc,address,size,user)
        if address==GATE:
            self.gate_return=int.from_bytes(uc.mem_read(uc.reg_read(x.UC_X86_REG_RSP),8),'little')
            self.events.append(dict(action='native_gate',code=uc.reg_read(x.UC_X86_REG_ECX),packet_id=uc.reg_read(x.UC_X86_REG_EDX)))
        if address==self.gate_return:self.events.append(dict(action='native_gate_return',value=uc.reg_read(x.UC_X86_REG_AL)))
        if address==APPLY:self.events.append(dict(action='native_player_apply'))
        if address not in self.handler_hooks:return super().hook(uc,address,size,user)
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        ctx=self.context;result=0
        if address in self.getters:result=ctx+self.getters[address]
        elif address in (0x14142d840,0x141421150,0x141420f70):uc.mem_write(a,bytes(16));result=a
        elif address in (0x141424430,0x14147d580,0x1413fe190):pass
        elif address==0x1445c83c0:uc.mem_write(b,bytes(16));result=b
        elif address==0x145f8a7a0:self.events.append(dict(action='gate_error_capture',code=a & 0xffffffff))
        elif address in (0x145d7bce0,0x145d7bf90,0x145d7db30):
            self.events.append(dict(action='nested_apply_capture',address=address,source_offset=b-(self.scratch+0x1018)))
        elif address==0x14143c260:uc.mem_write(a,bytes(uc.mem_read(b,16)));result=a
        elif address==0x1458819c0:uc.mem_write(a,bytes(16));result=a
        elif address==0x141482990:result=0
        elif address==RESET:
            if a!=ctx+0x1000 or b:raise ValueError('Player reset capture receiver')
            self.events.append(dict(action='player_reset_capture'))
        elif address==EXIT:self.events.append(dict(action='selection_exit_capture'))
        elif address==REFRESH:self.events.append(dict(action='manager_refresh_capture'))
        elif address==TEXT:uc.mem_write(b,bytes(16));result=b
        elif address==METADATA:
            uc.mem_write(b,struct.pack('<QQ',ctx+0x3600,ctx+0x3700) if self.fixture['metadata'] else bytes(16));result=b
        elif address==CLASS:result=5
        elif address==0x141876600:uc.mem_write(a,bytes(uc.mem_read(b,8)));result=a
        elif address==0x1417f24d0:result=0
        elif address==0x1463cca20:result=ctx+0xe000 if self.fixture['ui_present'] else 0
        elif address==0x1463dfb20:result=ctx+0xe000 if self.fixture['ui_present'] else 0
        elif address==0x144a1cbf0:result=int(self.fixture['ui_same'])
        elif address in self.actions:
            if address==0x1456140f0:self.events.append(dict(action='selection_event_capture',receiver=a,event=b & 255))
            elif address==0x1455960a0:self.events.append(dict(action='array1d8_entry_capture',raw_enum=b & 255,raw64=c))
            elif address==0x145d17ed0:self.events.append(dict(action='array238_entry_capture',index=b & 255,value=c & 255))
            elif address==0x14564e820:self.events.append(dict(action='metadata_capture',raw20=int.from_bytes(uc.mem_read(b,1),'little'),raw80=int.from_bytes(uc.mem_read(c,1),'little')))
            elif address==0x145c8b6b0:self.events.append(dict(action='code24b9_capture',offsets=[p-(self.scratch+0x1000) for p in (b,c,d)]))
            else:self.events.append(dict(action='backend_capture',address=address,receiver=a))
        self.finish(result)

    def execute(self,body,fixture):
        self.handler_phase=False;decoded=self.read_fields(body)
        if decoded['returned']!=1:raise ValueError('Complete decoded response required')
        self.fixture=fixture;self.events=[];self.gate_return=None;ctx=self.context
        self.uc.mem_write(ctx,bytes(0x20000))
        self.uc.mem_write(ctx+0x1000,struct.pack('<Q',ctx+0x1800))
        for offset,target in ((0x10,TEXT),(0x60,RESET),(0x80,CLASS),(0xa0,METADATA)):
            self.uc.mem_write(ctx+0x1800+offset,struct.pack('<Q',target))
        self.uc.mem_write(ctx+0x2008,struct.pack('<II',2,2))
        self.uc.mem_write(ctx+0x3038,struct.pack('<QQ',ctx+0x1000,ctx+0x2000))
        self.uc.mem_write(ctx+0x3620,bytes([7]));self.uc.mem_write(ctx+0x3708,struct.pack('<II',20,20))
        self.uc.mem_write(ctx+0x4008,bytes([fixture['gate_state']]))
        self.uc.mem_write(ctx+0x5000,struct.pack('<Q',ctx+0x5800))
        self.uc.mem_write(ctx+0x5838,struct.pack('<Q',EXIT))
        self.uc.mem_write(ctx+0x51a8,bytes([fixture['service_flag']]))
        self.uc.mem_write(ctx+0xa000,struct.pack('<Q',ctx+0xa800))
        self.uc.mem_write(ctx+0xa858,struct.pack('<Q',REFRESH))
        self.uc.mem_write(0x14b574a90,struct.pack('<Q',ctx+0x5000))
        self.uc.mem_write(0x14b520cc3,bytes([fixture['platform']]))
        self.handler_phase=True
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000
        self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,ctx),(x.UC_X86_REG_RDX,0x12345678),(x.UC_X86_REG_R8,self.scratch+0x1000)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(HANDLER,stop,count=500000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('Selection handler instruction budget')
        return dict(fixture=fixture,decoded=decoded,events=self.events.copy(),state=dict(
            raw8=int.from_bytes(self.uc.mem_read(ctx+0x1008,8),'little'),raw10=int.from_bytes(self.uc.mem_read(ctx+0x1010,4),'little'),
            vector_hex=bytes(self.uc.mem_read(ctx+0x1020,24)).hex(),rotation_hex=bytes(self.uc.mem_read(ctx+0x1038,24)).hex(),
            derived249=int.from_bytes(self.uc.mem_read(ctx+0x1249,1),'little'),flag24a=int.from_bytes(self.uc.mem_read(ctx+0x124a,1),'little'),
            service_flag=int.from_bytes(self.uc.mem_read(ctx+0x51a8,1),'little'),raw_f0=int.from_bytes(self.uc.mem_read(ctx+0x60f0,8),'little'),
            raw250=int.from_bytes(self.uc.mem_read(ctx+0x7250,8),'little'),owner_refs=int.from_bytes(self.uc.mem_read(ctx+0x2008,4),'little')))


def build():
    em=Emulator();cases=[]
    default=dict(gate_state=0,metadata=False,platform=False,ui_present=False,ui_same=False,service_flag=0)
    def add(code,update=None,flag348=255,flag349=255,enum260=255):
        fixture=dict(default,**(update or {}));fixture['code']=code
        data=bytearray(base.profile_body('',code));data[201]=flag348;data[202]=flag349;data[121]=enum260
        c=em.execute(bytes(data),fixture)
        special=code in (0x26,0x3c)
        accepted=not special and (code==0 or (code==0x1197 and fixture['gate_state']!=1))
        applies=[e for e in c['events'] if e['action']=='native_player_apply']
        if len(applies)!=int(accepted):raise ValueError('Handler acceptance mismatch '+str(c))
        if accepted:
            if c['state']['vector_hex']!=c['decoded']['vector188_hex'] or c['state']['owner_refs']!=2:
                raise ValueError('Handler player copy/reference mismatch')
            if (c['state']['derived249'],c['state']['flag24a'],c['state']['service_flag'])!=(int(enum260==2),int(bool(flag349)),1 if flag348 else fixture['service_flag']):
                raise ValueError('Handler normalized player/service flags mismatch')
            if [e['event'] for e in c['events'] if e['action']=='selection_event_capture']!=[1]:raise ValueError('Actual service event not emitted')
        else:
            if any(c['state'][key] for key in ('raw8','raw10','derived249','flag24a','raw_f0','raw250')):raise ValueError('Rejected response changed player/state')
        cases.append(c)
    for gate_state in (0,1):
        for code in (0,1,14,0x26,0x3c,0x1197,0x24b8,0x24b9,9818,9819,90021,0xffffffff):add(code,dict(gate_state=gate_state))
    for update in (dict(metadata=True),dict(platform=True),dict(service_flag=1)):
        add(0,update,flag348=0,flag349=0,enum260=2)
    for same in (False,True):add(0x3c,dict(ui_present=True,ui_same=same))
    maps=base.base
    for count in (1,8):
        arrays=maps.main_arrays();arrays[0x1d8]=tuple((255,i+100) for i in range(count));arrays[0x238]=tuple((i+10,) for i in range(count))
        data=maps.body_bytes(((1,maps.value_fixture(1,((255,255,2,3),),(4,5))),),((1,255,2,3,4,5),),arrays)
        c=em.execute(data,dict(default,code=0,case='nonempty-'+str(count)))
        if c['state']['vector_hex']!=c['decoded']['vector188_hex'] or c['state']['owner_refs']!=2:raise ValueError('Nonempty body application mismatch')
        items=[e for e in c['events'] if e['action']=='array1d8_entry_capture']
        if items!=[dict(action='array1d8_entry_capture',raw_enum=91,raw64=i+100) for i in range(count)]:raise ValueError('Array1D8 handoff mismatch')
        items=[e for e in c['events'] if e['action']=='array238_entry_capture']
        if items!=[dict(action='array238_entry_capture',index=i+1,value=i+10) for i in range(count)]:raise ValueError('Array238 one-based handoff mismatch')
        cases.append(c)
    # Verify the apparent text consumer against actual call instructions and
    # the PE import table; this path must not be labelled a position getter.
    path=HERE/'build-object-zero-init-code.py'
    spec=importlib.util.spec_from_file_location('select_handler_imports',path)
    imports=importlib.util.module_from_spec(spec);spec.loader.exec_module(imports)
    title_fragments=native.decode_ranges(em.image,{em.image.roots[em.image.containing(0x145dea660)]})
    title_imports=[]
    for fragment in title_fragments:
        for ins in fragment['instructions']:
            if ins['mnemonic']!='call':continue
            slots=list(ins['rip_references']);target=ins.get('direct_target')
            if target:
                off=em.image.offset(target-em.image.pe.base)
                if em.raw[off:off+2]==b'\xff\x25':slots.append(target+6+struct.unpack_from('<i',em.raw,off+2)[0])
            for slot in slots:
                try:entry=imports.import_at(em.raw,em.image,slot)
                except ValueError:continue
                title_imports.append(dict(call_address=ins['address'],slot=slot,**entry))
    if not {'GetActiveWindow','SetWindowTextW'}<={row['name'] for row in title_imports}:
        raise ValueError('Window title consumer imports changed')
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),handler_ranges=em.handler_ranges,
        leaves=em.handler_leaves,dependency_sha256={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-character-select-fields.py','replay-character-select-maps.py','replay-character-select-apply.py')},
        crt=em.math_crt,cases=cases,title_fragments=title_fragments,title_imports=title_imports,native_execution=True,network_ready=False,
        limitations=['Actual whole body reader, result gate, handler, player shared-reference acquire, apply and service event method execute.',
            'Managers, player/vtables/metadata/reference owners are synthetic; diagnostics, nested applies, class/text copy, UI/backend calls and virtual methods are captures.',
            'Player listener list empty; platform objects have empty callback fields; weak manager target absent. Other backend/lifetime paths unverified.',
            'No world-coordinate consumer, engine lifecycle, socket/device confirmation/live session/game process/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-select-handler-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
