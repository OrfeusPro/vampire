"""Native LoginResult body reader then handler/gate with explicit backend fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('login_handler_reader', HERE/'replay-login-result-reader.py')
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
native, x = reader.native, reader.x
HANDLER, GATE = 0x146765540, 0x1467a8e10
EXIT, SDK_CALLBACK, VIEW = 0x30001000, 0x30001010, 0x30001020


class Emulator(reader.Emulator):
    def __init__(self):
        super().__init__()
        self.handler_phase = False
        self.handler_fragments = native.decode_ranges(self.image, {
            self.image.roots[self.image.containing(HANDLER)]})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.handler_fragments)
        # Gate contains inline switch data. Keep PE ranges intact and record only
        # instructions actually reached, instead of pretending data is linear code.
        root=self.image.roots[self.image.containing(GATE)]
        self.gate_ranges=[]
        self.gate_trace={}
        for r in self.image.ranges:
            if self.image.roots[r]!=root: continue
            begin,end,_=r
            offset=self.image.offset(begin)
            data=self.raw[offset:offset+end-begin]
            self.gate_ranges.append(dict(begin=self.image.pe.base+begin,end=self.image.pe.base+end,
                file_offset=offset,sha256=hashlib.sha256(data).hexdigest()))
            self.ranges.append((self.image.pe.base+begin,self.image.pe.base+end))
        self.handler_leaves = []
        packet = next(p for p in self.bindings['packets'] if p['name']=='PktLoginResult')
        cs = native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
        cs.detail = True
        for address,length in ((packet['id_getter'],6),(0x144aaa9d0,8),(0x144aaaab0,12),
            (0x144aaa9b0,9),(0x144aaaa10,11),(0x1456048a0,8),(0x1456048e0,8)):
            offset = self.image.offset(address-self.image.pe.base)
            data = self.raw[offset:offset+length]
            refs = [i.address+i.size+op.mem.disp for i in cs.disasm(data,address) for op in i.operands
                if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
            self.handler_leaves.append(dict(address=address,file_offset=offset,bytes=data.hex(),rip_references=refs))
            self.ranges.append((address,address+length))
        self.getter_globals = {r['address']:r['rip_references'][0] for r in self.handler_leaves if r['rip_references']}
        if self.getter_globals[0x144aaa9d0]!=0x14b520d90:
            raise ValueError('Login handler singleton getter changed')
        self.handler_hooks = {0x14142d840,0x141424430,0x14147d580,0x141421150,0x1413fe190,
            0x141420cc0,0x14143c260,0x14558edf0,0x145f8a7a0,0x145c859f0,0x145d37270,
            0x145d46a70,0x144aa8880,0x144aa8860,0x1445c6880,0x1445d1210,0x145c8b1b0,
            0x146410f10,0x144a55e30,0x146423fb0,0x1467259c0,0x146486a50,
            0x145be59b0,0x145c0a1b0,0x145be5fb0,0x145a2f050,0x145a4b8d0,0x1466fd130,
            0x146644820,0x146651060,0x145e0c6c0,0x145e182d0,0x144a717e0,
            0x1445c6860,0x1445c83c0,0x144a4b1c0,0x144a4af10,0x14676a270,0x145c8b6b0,
            0x144aabb60,0x1456048f0,0x14563d980,0x145636eb0,0x14563bb80,EXIT,SDK_CALLBACK,VIEW}
        rows = [r for f in self.handler_fragments for r in f['instructions']]
        gate_call = next(r for r in rows if r.get('direct_target')==GATE)
        self.gate_return = gate_call['address']+len(bytes.fromhex(gate_call['bytes']))
        pages = {p for begin,end in self.ranges for p in range(begin & ~4095,(end+4095) & ~4095,4096)}
        pages.update(a & ~4095 for a in (*self.handler_hooks,*self.getter_globals.values(),0x149d81080))
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()): continue
            self.uc.mem_map(page,4096)
            try: offset = self.image.offset(page-self.image.pe.base)
            except ValueError: continue
            self.uc.mem_write(page,self.raw[offset:offset+4096])
        self.context = 0x21000000
        self.uc.mem_map(self.context,0x10000)
        self.uc.hook_add(reader.base.ping.unicorn.UC_HOOK_MEM_WRITE,self.memory_hook)

    def memory_hook(self,uc,access,address,size,value,user):
        if not self.handler_phase: return
        region=None
        if self.context+0x1000<=address<self.context+0x1200:
            region,offset='state',address-(self.context+0x1000)
        elif self.context+0x2308<=address<self.context+0x2310:
            region,offset='controller',address-(self.context+0x2000)
        elif address in (0x14b571319,0x14b4f3458):
            region,offset='global',address
        if region:
            self.native_writes.append(dict(region=region,offset=offset,size=size,
                value=value & ((1 << (size*8))-1),instruction=uc.reg_read(x.UC_X86_REG_RIP)))

    def fwrite(self,desc,text):
        data = text.encode('utf-16le')+b'\0\0' if text else b''
        pointer = self.alloc(len(data)) if data else 0
        if data: self.uc.mem_write(pointer,data)
        self.uc.mem_write(desc,struct.pack('<QII',pointer,len(data)//2,len(data)//2))

    def fread(self,desc):
        pointer,n,cap = struct.unpack('<QII',bytes(self.uc.mem_read(desc,16)))
        if not 0<=n<=cap<=512: raise ValueError('Handler FString fixture bound')
        if not n: return ''
        data = bytes(self.uc.mem_read(pointer,n*2))
        if not data.endswith(b'\0\0'): raise ValueError('Handler FString fixture terminator')
        return data[:-2].decode('utf-16le')

    def hook(self,uc,address,size,user):
        if not self.handler_phase:
            return super().hook(uc,address,size,user)
        if address==GATE:
            self.events.append(dict(action='native_gate',code=uc.reg_read(x.UC_X86_REG_ECX),packet_id=uc.reg_read(x.UC_X86_REG_EDX)))
        if address==self.gate_return:
            self.events.append(dict(action='native_gate_return',value=uc.reg_read(x.UC_X86_REG_AL)))
        if any(r['begin']<=address<r['end'] for r in self.gate_ranges):
            cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
            cs.detail=True
            data=bytes(uc.mem_read(address,size))
            rows=list(cs.disasm(data,address))
            if len(rows)!=1 or rows[0].size!=size: raise ValueError('Gate executed instruction decode')
            i=rows[0]
            refs=[i.address+i.size+op.mem.disp for op in i.operands if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
            self.gate_trace[address]=dict(address=address,file_offset=self.image.offset(address-self.image.pe.base),
                bytes=data.hex(),mnemonic=i.mnemonic,operands=i.op_str,rip_references=refs)
            for ref in refs:
                page=ref & ~4095
                if any(lo<=page<=hi for lo,hi,_ in uc.mem_regions()): continue
                off=self.image.offset(page-self.image.pe.base)
                uc.mem_map(page,4096)
                uc.mem_write(page,self.raw[off:off+4096])
        if address not in self.handler_hooks:
            return super().hook(uc,address,size,user)
        a,b,c,d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result = 0
        ctx = self.context
        event = None
        if address in (0x14142d840,0x141421150): self.fwrite(a,'')
        elif address in (0x141424430,0x14147d580,0x1413fe190): pass
        elif address in (0x141420cc0,0x14143c260): self.fwrite(a,self.fread(b)); result=a
        elif address==0x14558edf0: result=ctx+0x6000
        elif address==0x145f8a7a0: event=dict(action='gate_error_capture',code=a & 0xffffffff,mode=b)
        elif address==0x145c859f0: result=ctx+0x1000
        elif address==0x145d37270: result=ctx+0x2000
        elif address==0x145d46a70: event=dict(action='early_state_helper_capture')
        elif address in (0x144aa8880,0x1445c6880,0x145be59b0,0x145a2f050,0x1445c6860,0x14563d980): result=ctx+0x7000
        elif address==0x144aa8860: event=dict(action='clock_helper_capture')
        elif address==0x1445d1210: event=dict(action='time_pair_capture',raw64=b,raw16=c & 65535)
        elif address==0x145c8b1b0: event=dict(action='state_toggle_capture',value=b & 255)
        elif address in (0x146410f10,0x146644820,0x145e0c6c0): result=ctx+0x7000 if self.fixture['optional_object'] else 0
        elif address==0x144a55e30: event=dict(action='optional_object_prepare_capture')
        elif address==0x146423fb0: event=dict(action='positive_field_helper_capture',value=b & 0xffffffff)
        elif address==0x1467259c0: event=dict(action='post_state_capture',address=address)
        elif address==0x146486a50: result=ctx+0x8000
        elif address==0x145c0a1b0: event=dict(action='server_id_helper_capture',raw32=b & 0xffffffff)
        elif address==0x145be5fb0: result=int(self.fixture['post_predicate'])
        elif address==0x145a4b8d0: event=dict(action='post_predicate_helper_capture',raw_value=b)
        elif address==0x1466fd130: event=dict(action='flag138_helper_capture',raw_value=a)
        elif address==0x146651060: event=dict(action='special_error_object_capture',code=b & 0xffffffff)
        elif address==0x145e182d0: event=dict(action='special_90021_object_capture')
        elif address==0x144a717e0: event=dict(action='special_error_finish_capture',raw_value=a)
        elif address==0x1445c83c0: self.fwrite(b,'localized-fixture')
        elif address==0x144a4b1c0: event=dict(action='error54_popup_capture')
        elif address==0x144a4af10: event=dict(action='generic_popup_capture')
        elif address==0x14676a270: event=dict(action='dedicated_error_capture',code=b & 0xffffffff)
        elif address==0x145c8b6b0: event=dict(action='error9400_fields_capture',offsets=[v-(self.scratch+0x1000) for v in (b,c,d)])
        elif address==0x144aabb60: event=dict(action='disconnect_backend_capture',raw_value=b,peer_argument=a==ctx+0xb000)
        elif address==0x1456048f0: self.fwrite(b,'sdk-fixture'); result=b
        elif address==0x145636eb0: event=dict(action='sdk_final_helper_capture')
        elif address==0x14563bb80: event=dict(action='sdk_a0_helper_capture')
        elif address==EXIT: event=dict(action='exit_virtual_capture',raw_value=b)
        elif address==SDK_CALLBACK: event=dict(action='sdk_88_virtual_capture')
        elif address==VIEW: event=dict(action='view_virtual_capture')
        else: raise ValueError('Missing handler fixture '+hex(address))
        if event: self.events.append(event)
        uc.reg_write(x.UC_X86_REG_RAX,result)
        sp = uc.reg_read(x.UC_X86_REG_RSP)
        ret = int.from_bytes(uc.mem_read(sp,8),'little')
        uc.reg_write(x.UC_X86_REG_RSP,sp+8)
        uc.reg_write(x.UC_X86_REG_RIP,ret)

    def execute_handler(self,body,fixture):
        self.handler_phase=False
        decoded=self.read(body)
        if decoded['returned']!=1: raise ValueError('Handler requires complete native body')
        ctx=self.context
        self.uc.mem_write(ctx,bytes(0x10000))
        self.fixture,self.events=fixture,[]
        self.native_writes=[]
        state,controller,manager,wrapper,peer=ctx+0x1000,ctx+0x2000,ctx+0x3000,ctx+0xa000,ctx+0xb000
        self.fwrite(state+0x28,'before-fixture')
        self.uc.mem_write(state+0x38,struct.pack('<Q',0xabcdef))
        self.uc.mem_write(controller+0x308,struct.pack('<II',fixture['previous_server'],fixture['previous_server']))
        self.uc.mem_write(wrapper+0x10,struct.pack('<Q',peer))
        self.uc.mem_write(peer+0x270,struct.pack('<I',fixture['selected_server']))
        self.uc.mem_write(peer+0x2a6,bytes([fixture['peer_flag']]))
        self.uc.mem_write(ctx+0x6008,bytes([fixture['gate_state']]))
        for getter,value in ((0x144aaa9d0,wrapper),(0x1456048a0,manager if fixture['manager_present'] else 0),(0x1456048e0,ctx+0x5000)):
            self.uc.mem_write(self.getter_globals[getter],struct.pack('<Q',value))
        self.uc.mem_write(ctx+0x5000,struct.pack('<Q',ctx+0x9000))
        self.uc.mem_write(ctx+0x9038,struct.pack('<Q',EXIT))
        self.uc.mem_write(ctx+0x8000,struct.pack('<Q',ctx+0x9100))
        self.uc.mem_write(ctx+0x9128,struct.pack('<Q',VIEW))
        self.uc.mem_write(manager+0x88,struct.pack('<Q',ctx+0xc000 if fixture['sdk_callbacks'] else 0))
        self.uc.mem_write(ctx+0xc000,struct.pack('<Q',ctx+0x9200))
        self.uc.mem_write(ctx+0x9220,struct.pack('<Q',SDK_CALLBACK))
        self.uc.mem_write(manager+0xa0,struct.pack('<Q',ctx+0xd000 if fixture['sdk_callbacks'] else 0))
        self.uc.mem_write(manager+0x38,struct.pack('<Q',ctx+0xe000 if fixture['auth_present'] else 0))
        self.uc.mem_write(0x14b520cc3,bytes([fixture['sdk_enabled']]))
        self.uc.mem_write(0x14b571319,b'\0')
        self.uc.mem_write(0x14b4f3458,struct.pack('<q',0xabcdef))
        self.handler_phase=True
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000
        self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,ctx+0x4000),(x.UC_X86_REG_RDX,0x12345678),(x.UC_X86_REG_R8,self.scratch+0x1000)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(HANDLER,stop,count=250000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop: raise ValueError('LoginResult handler instruction budget')
        state_result=dict(text=self.fread(state+0x28),
            qwords={hex(o):int.from_bytes(self.uc.mem_read(state+o,8),'little') for o in (0x38,0x88,0xb0,0xc0,0xd0,0xe0)},
            flags={hex(o):int.from_bytes(self.uc.mem_read(state+o,1),'little') for o in (0xa0,0xe8)})
        return dict(fixture=fixture,decoded=decoded,events=self.events,native_writes=self.native_writes,state=state_result,
            controller_server=list(struct.unpack('<II',bytes(self.uc.mem_read(controller+0x308,8)))),
            special22_flag=int.from_bytes(self.uc.mem_read(0x14b571319,1),'little'),
            derived_integer=struct.unpack('<q',bytes(self.uc.mem_read(0x14b4f3458,8)))[0])


def build():
    path=native.ROOT/'code-clues/login-result-reader-replay.json'
    prior=json.loads(path.read_text('utf-8'))
    emulator=Emulator()
    if prior['sha256']!=emulator.bindings['sha256']: raise ValueError('Login handler source mismatch')
    fields=prior['cases'][0]['fields']
    fields=dict(fields,strings=dict(fields['strings'],**{'0x18':'response-text-fixture'}))
    default=dict(gate_state=0,peer_flag=0,selected_server=42,previous_server=7,optional_object=True,
        post_predicate=False,sdk_enabled=False,manager_present=True,sdk_callbacks=False,auth_present=False)
    cases=[]
    for value in (0,1,32767,32768,65535):
        for peer in (0,1):
            current=dict(fields,u16=dict(fields['u16'],**{'0x48':value}))
            f=dict(default,name='success-field-'+str(value)+'-peer-'+str(peer),peer_flag=peer)
            cases.append(emulator.execute_handler(reader.payload(current),f))
    for code in (1,14,22,37,54,9400,9818,9819,90021,0xffffffff):
        current=dict(fields,u32=dict(fields['u32'],**{'0x10':code}))
        cases.append(emulator.execute_handler(reader.payload(current),dict(default,name='code-'+str(code))))
    for update in (dict(name='gate-state-one',gate_state=1),dict(name='server-unchanged',previous_server=42),
        dict(name='post-predicate',post_predicate=True),dict(name='sdk-manager-absent',sdk_enabled=True,manager_present=False),
        dict(name='sdk-empty-manager',sdk_enabled=True),dict(name='sdk-full',sdk_enabled=True,sdk_callbacks=True,auth_present=True),
        dict(name='sdk-callbacks-no-auth',sdk_enabled=True,sdk_callbacks=True),
        dict(name='sdk-auth-no-callbacks',sdk_enabled=True,auth_present=True)):
        cases.append(emulator.execute_handler(reader.payload(fields),dict(default,**update)))
    for code in (1,9818,9819,90021):
        current=dict(fields,u32=dict(fields['u32'],**{'0x10':code}),strings=dict(fields['strings'],**{'0x38':'error-message-fixture'}))
        cases.append(emulator.execute_handler(reader.payload(current),dict(default,name='variant-'+str(code),optional_object=False)))
    current=dict(fields,u32=dict(fields['u32'],**{'0x10':1}))
    cases.append(emulator.execute_handler(reader.payload(current),dict(default,name='gate-state-one-error',gate_state=1)))
    current=dict(fields,u16=dict(fields['u16'],**{'0x48':1}))
    cases.append(emulator.execute_handler(reader.payload(current),dict(default,name='positive-object-absent',optional_object=False)))
    current=dict(fields,bool=dict(fields['bool'],**{'0x138':0}))
    cases.append(emulator.execute_handler(reader.payload(current),dict(default,name='flag138-zero')))
    for value in (0,1,65535):
        current=dict(fields,u16=dict(fields['u16'],**{'0x60':value}))
        cases.append(emulator.execute_handler(reader.payload(current),dict(default,name='raw16-'+str(value))))
    constants=[]
    for address in (0x1489be1b8,0x14898d1c8):
        off=emulator.image.offset(address-emulator.image.pe.base)
        data=emulator.raw[off:off+8]
        constants.append(dict(address=address,file_offset=off,bytes=data.hex(),double=struct.unpack('<d',data)[0]))
    off=emulator.image.offset(0x149d81080-emulator.image.pe.base)
    table=emulator.raw[off:off+24]
    if struct.unpack_from('<Q',table,16)[0]!=HANDLER: raise ValueError('Login handler table changed')
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fragments=emulator.handler_fragments,gate_ranges=emulator.gate_ranges,
        gate_trace=[emulator.gate_trace[a] for a in sorted(emulator.gate_trace)],
        leaves=emulator.handler_leaves,getter_globals={hex(k):v for k,v in emulator.getter_globals.items()},
        handler_table=dict(address=0x149d81080,file_offset=off,bytes=table.hex()),constants=constants,cases=cases,
        native_execution=True,network_ready=False,
        limitations=['Actual complete body reader then native LoginResult handler and covered gate branches execute in same emulator.',
            'State/service/controller getters, diagnostics, string copies, UI/SDK callbacks, clock/persistence/disconnect/post-state are fixtures/captures.',
            'Singleton/manager getters and selected-server/peer-flag leaves execute against synthetic objects; no real state.',
            'Result gate only covered codes; unsupported targets fail closed. No claim all error/UI/policy branches are covered.',
            'Post-state function captured, not character request execution; no listener/Dispatch/server/session proof.',
            'No game launch/profile/process memory/credentials/network/Android.'])


if __name__=='__main__':
    report=build()
    path=native.ROOT/'code-clues/login-result-handler-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
