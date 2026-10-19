"""Execute native SDK result handoff and queued thunk with explicit delegate fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('dispatch_completion', HERE/'replay-sdk-sign-in-completion.py')
completion = importlib.util.module_from_spec(spec)
spec.loader.exec_module(completion)
native, x = completion.native, completion.x
unicorn = completion.gates.fields.lifecycle.guid.unicorn
DISPATCH, THUNK = 0x1444dff20, 0x1444d83b0
CLONE, DESTROY, INVOKE = 0x30000000, 0x30000010, 0x30000020


class Replay:
    def __init__(self, raw, image, fragments, fixture):
        self.fixture = fixture
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        self.allowed = {r['address'] for f in fragments
                        if f['root_begin_rva'] in (DISPATCH-image.pe.base, THUNK-image.pe.base,
                                                   0x1414203f0-image.pe.base,0x1444bee50-image.pe.base)
                        for r in f['instructions']}
        rows = [r for f in fragments for r in f['instructions'] if r['address'] in self.allowed]
        pages = {a & ~4095 for r in rows for a in
                 [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        self.hooks = {0x14148a060,0x141404350,0x1414311c0,0x14147d580}
        pages.update(a & ~4095 for a in self.hooks)
        for page in sorted(pages):
            self.uc.mem_map(page,4096)
            try: off=image.offset(page-image.pe.base)
            except ValueError: continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.base=0x20000000
        self.uc.mem_map(self.base,0x80000)
        self.uc.mem_map(CLONE,4096)
        self.uc.mem_write(0x14b4f2060,b'\0')  # Logging disabled fixture.
        self.cursor=self.base+0x10000
        self.stack,self.stop=self.base+0x70000,self.base+0x7f000
        self.auth,self.shared,self.ref=self.base+0x1000,self.base+0x2000,self.base+0x3000
        self.vtable,self.original=self.base+0x4000,self.base+0x5000
        self.uc.mem_write(self.vtable,struct.pack('<Q',DESTROY))
        self.uc.mem_write(self.vtable+0x40,struct.pack('<Q',CLONE))
        self.uc.mem_write(self.vtable+0x60,struct.pack('<Q',INVOKE))
        self.uc.mem_write(self.original,struct.pack('<Q',self.vtable))
        if fixture['bound']:
            self.uc.mem_write(self.auth+0x98,struct.pack('<QI',self.original,1))
        self.uc.mem_write(self.shared,struct.pack('<QQ',self.base+0x6000,self.ref if fixture['refcounted'] else 0))
        self.uc.mem_write(self.ref+8,struct.pack('<II',4,4))
        self.events=[]; self.queued=None; self.allocations=[]
        self.uc.hook_add(unicorn.UC_HOOK_CODE,self.hook)

    def allocate(self,size):
        if not 0<size<=4096 or self.cursor+size>=self.base+0x60000:
            raise ValueError('Dispatch allocation fixture bound')
        result=self.cursor;self.cursor+=(size+15)&~15
        return result

    def hook(self,uc,address,size,user):
        if address in self.allowed:return
        a,b,c,d=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        result=0
        if address==CLONE:
            pointer=self.allocate(16)
            uc.mem_write(pointer,struct.pack('<Q',self.vtable))
            uc.mem_write(b,struct.pack('<QI',pointer,1))
            self.events.append(dict(action='delegate_clone_fixture'))
        elif address==DESTROY:
            self.events.append(dict(action='delegate_destroy_capture',original=a==self.original))
        elif address==INVOKE:
            pair=bytes(uc.mem_read(b,16))
            if pair!=bytes(uc.mem_read(self.shared,16)):raise ValueError('Dispatch lost response pair')
            self.events.append(dict(action='delegate_execute_capture',original_response_pair=True,
                                    returned=self.fixture['execute_ok']))
            result=int(self.fixture['execute_ok'])
        elif address==0x14148a060:
            if (a,b)!=(48,8):raise ValueError('Closure allocation changed')
            result=self.allocate(a);self.allocations.append(result)
        elif address==0x141404350:
            thunk=struct.unpack('<Q',bytes(uc.mem_read(b,8)))[0]
            closure=struct.unpack('<Q',bytes(uc.mem_read(b+16,8)))[0]
            if a!=1 or thunk!=THUNK or closure!=self.allocations[-1]:
                raise ValueError('Task descriptor changed')
            self.queued=(thunk,closure+8)
            uc.mem_write(b,b'\0'*8)  # Scheduler move fixture, no native task graph executed.
            uc.mem_write(b+16,b'\0'*8)
            self.events.append(dict(action='task_schedule_capture',selector=a,thunk=thunk))
        elif address==0x1414311c0:
            if (b,c,d)!=(0,0,16):raise ValueError('Delegate release fixture changed')
            uc.mem_write(a,struct.pack('<QI',0,0))
        elif address==0x14147d580:
            self.events.append(dict(action='free_capture'))
        else:raise ValueError('Unexpected dispatch instruction '+hex(address))
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP)
        target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

    def run(self,address,rcx,rdx=0):
        self.uc.mem_write(self.stack,struct.pack('<Q',self.stop))
        for reg,value in ((x.UC_X86_REG_RSP,self.stack),(x.UC_X86_REG_RCX,rcx),(x.UC_X86_REG_RDX,rdx)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(address,self.stop,count=4096)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=self.stop:raise ValueError('Dispatch instruction budget')

    def capture(self):
        self.run(DISPATCH,self.auth,self.shared)
        original_cleared=int.from_bytes(self.uc.mem_read(self.auth+0xa0,4),'little')==0
        count_after_dispatch=int.from_bytes(self.uc.mem_read(self.ref+8,4),'little')
        thunk,payload=self.queued
        stored_pair=bytes(self.uc.mem_read(payload+0x18,16))==bytes(self.uc.mem_read(self.shared,16))
        self.events.append(dict(action='fixture_task_drain'))
        self.run(thunk,payload)
        return dict(fixture=self.fixture,original_delegate_cleared=original_cleared,
                    closure_has_original_response_pair=stored_pair,
                    strong_count_after_dispatch=count_after_dispatch,
                    strong_count_after_thunk=int.from_bytes(self.uc.mem_read(self.ref+8,4),'little'),events=self.events)



class NativeBindingReplay(Replay):
    """Real binder and real delegate virtual clone/invoke; TFunction storage fixtures."""
    def __init__(self, raw, image, fragments, fixture):
        super().__init__(raw,image,fragments,fixture)
        roots=(0x1444ba4f0,0x144237840,0x14423aaf0)
        rows=[r for f in fragments if image.pe.base+f['root_begin_rva'] in roots for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        pages={a & ~4095 for r in rows for a in [r['address'],r['address']+len(bytes.fromhex(r['bytes']))-1,*r['rip_references']]}
        pages.update(a & ~4095 for a in (0x1414276b0,0x141429520,0x141547160))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=image.offset(page-image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,raw[off:off+4096])
        self.function_vtable,self.function_input=self.base+0x7000,self.base+0x8000
        self.context=self.base+0xa000
        self.uc.mem_write(self.function_vtable,struct.pack('<QQ',CLONE+0x40,CLONE+0x50))
        self.uc.mem_write(self.function_input,struct.pack('<Q',CLONE+0x60))
        storage=self.base+0x9000 if fixture['heap_storage'] else self.function_input+0x20
        self.uc.mem_write(storage,struct.pack('<Q',self.function_vtable))
        self.uc.mem_write(self.function_input+0x10,struct.pack('<Q',storage if fixture['heap_storage'] else 0))
        self.uc.mem_write(self.auth+0x98,b'\0'*16)
        self.run(0x1444ba4f0,self.auth+0x98,self.function_input)
        self.original=struct.unpack('<Q',bytes(self.uc.mem_read(self.auth+0x98,8)))[0]
        self.events=[]

    def hook(self,uc,address,size,user):
        if address==0x1444d83d0:
            self.events.append(dict(action='native_delegate_return',al=uc.reg_read(x.UC_X86_REG_RAX)&255))
        if address in self.allowed:return
        a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
        result=0
        if address==0x1414276b0:
            if a!=96:raise ValueError('Native delegate allocation size changed')
            result=self.allocate(a)
            uc.mem_write(b,struct.pack('<QI',result,1))
            self.events.append(dict(action='delegate_allocation_fixture'))
        elif address==0x141429520:result=0x1234
        elif address==0x141547160:
            self.events.append(dict(action='delegate_destroy_capture',original=a==getattr(self,'original',None)))
        elif address==CLONE+0x40:
            storage=self.allocate(16)
            uc.mem_write(storage,struct.pack('<Q',self.function_vtable))
            uc.mem_write(b,struct.pack('<Q',storage))
            self.events.append(dict(action='function_storage_clone_fixture'))
        elif address==CLONE+0x50:result=self.context
        elif address==CLONE+0x60:
            if a!=self.context or bytes(uc.mem_read(b,16))!=bytes(uc.mem_read(self.shared,16)):
                raise ValueError('Native bound function arguments changed')
            result=int(self.fixture['execute_ok'])
            self.events.append(dict(action='bound_function_capture',original_response_pair=True,returned=result))
        else:return super().hook(uc,address,size,user)
        uc.reg_write(x.UC_X86_REG_RAX,result)
        rsp=uc.reg_read(x.UC_X86_REG_RSP)
        target=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)

def build():
    path=native.ROOT/'code-clues/sdk-sign-in-completion-replay.json'
    prior=json.loads(path.read_text('utf-8'));raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:raise ValueError('Dispatch source changed')
    image=native.Image(raw)
    addresses=(DISPATCH,THUNK,0x1414203f0,0x1444bee50,0x141404350,0x1444d20d0,0x1444ba4f0,0x144237840,0x14423aaf0)
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in addresses})
    cases=[]
    for bound in (False,True):
        for refcounted in (False,True):
            for execute_ok in (False,True):
                fixture=dict(bound=bound,refcounted=refcounted,execute_ok=execute_ok)
                cases.append(Replay(raw,image,fragments,fixture).capture())
    native_cases=[]
    for refcounted in (False,True):
        for heap_storage in (False,True):
            for execute_ok in (False,True):
                fixture=dict(bound=True,refcounted=refcounted,heap_storage=heap_storage,execute_ok=execute_ok)
                native_cases.append(NativeBindingReplay(raw,image,fragments,fixture).capture())
    request_path=native.ROOT/'code-clues/sdk-sign-in-body-replay.json'
    request=json.loads(request_path.read_text('utf-8'))
    if request['sha256']!=prior['sha256']:raise ValueError('Binding request source changed')
    binding=[r for f in request['fragments'] for r in f['instructions'] if 0x1444fb8b4<=r['address']<0x1444fb8cb]
    for row in binding:
        off=image.offset(row['address']-image.pe.base)
        if raw[off:off+len(bytes.fromhex(row['bytes']))].hex()!=row['bytes']:
            raise ValueError('SignIn binding instruction changed')
    table_address=0x149424db0
    table_offset=image.offset(table_address-image.pe.base)
    table_bytes=raw[table_offset:table_offset+104]
    slots=list(struct.unpack('<'+'Q'*13,table_bytes))
    if slots[8]!=0x144237840 or slots[12]!=0x14423aaf0:
        raise ValueError('Native delegate vtable changed')
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                completion_report_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                request_report_sha256=hashlib.sha256(request_path.read_bytes()).hexdigest(),
                sign_in_binding_instructions=binding,
                fragments=fragments,cases=cases,native_binding_cases=native_cases,
                delegate_vtable=dict(address=table_address,file_offset=table_offset,bytes=table_bytes.hex(),
                                     sha256=hashlib.sha256(table_bytes).hexdigest(),slots=slots),
                native_execution=True,network_ready=False,
                limitations=[
                    'Native dispatcher, delegate copy wrapper, closure construction, local cleanup and queued thunk execute.',
                    'Base cases use fixture delegates; native_binding_cases execute binder, actual virtual clone and slot+0x60 bridge.',
                    'Bound function/TFunction storage clone/get-context and destructor/allocation remain fixtures; real game receiver unproven.',
                    'Task scheduler is a capture/move fixture; task selector 1 has no claimed thread semantics.',
                    'Queued thunk is drained explicitly by harness after dispatcher returns; no real task graph or race coverage.',
                    'Refcount fixture starts above zero; final destruction and closure lifetime termination are outside scope.',
                    'No game launch, process memory, profile, credentials or HTTP used.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/sdk-result-dispatch-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases'])+len(report['native_binding_cases']))))
