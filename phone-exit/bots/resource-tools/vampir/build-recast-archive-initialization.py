"""Execute Linker flag initialization, structured archive binding and actor tail.

Client instructions establish flags and version lookup. Source registry rows,
preallocated memory and the already decoded property-end375 are explicit inputs.
FString uses a bounded ANSI replacement. No game/OS/global registry execution.
"""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
transfer=load('archive_init_transfer','build-recast-archive-transfer.py')

class InitializationReplay(transfer.TransferReplay):
    def __init__(self,root):
        super().__init__(root);native=load('archive_init_native','build-native-entry-code.py')
        roots=[0x14173c480,0x141734500,0x1417349c0,0x14173eb10,0x14381b2b0,0x14173a560,0x144351d20,0x141544ba0,0x141422070,0x141593500]
        extra=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in roots})
        self.fragments+=extra;self.allowed.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in extra)
        self.initialization_bindings=[];self.initialization_leaves=[]
        for slot in [0x68,0x70,0xb0,0xf0]:
            off=self.image.offset(transfer.TABLE+slot-self.image.pe.base);target=struct.unpack_from('<Q',self.data,off)[0]
            self.initialization_bindings.append(dict(table=transfer.TABLE,slot=slot,target=target,file_offset=off,raw_hex=self.data[off:off+8].hex()))
        decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
        for address in [r['target'] for r in self.initialization_bindings]+[0x141593610,0x141599f90]:
            off=self.image.offset(address-self.image.pe.base);rows=[]
            for ins in decoder.disasm(self.data[off:off+48],address):
                if ins.mnemonic in ['call','jmp']:raise ValueError('Unexpected non-leaf archive initializer')
                rows.append(dict(address=ins.address,bytes=bytes(ins.bytes).hex(),mnemonic=ins.mnemonic,operands=ins.op_str))
                if ins.mnemonic=='ret':break
            if not rows or rows[-1]['mnemonic']!='ret':raise ValueError('Initializer leaf bound')
            size=sum(len(bytes.fromhex(r['bytes'])) for r in rows)
            self.initialization_leaves.append(dict(address=address,file_offset=off,raw_hex=self.data[off:off+size].hex(),instructions=rows))
            self.allowed.append((address,address+size))
        self.allocations=[];self.strings=[];self.version_calls=[]

    def native_return(self,value=None):
        uc=self.uc;x=self.x;rsp=uc.reg_read(x.UC_X86_REG_RSP);ret=struct.unpack('<Q',uc.mem_read(rsp,8))[0]
        if value is not None:uc.reg_write(x.UC_X86_REG_RAX,value)
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,ret)

    def guard(self,uc,address,size,_):
        if address in [0x14173c4e9,0x14173a9e2,0x144351d5d,0x14381b409]:self.stop=address;uc.emu_stop();return
        x=self.x
        if address==0x141597dd0:
            pointer=uc.reg_read(x.UC_X86_REG_RDX);off=self.image.offset(pointer-self.image.pe.base)
            self.version_calls.append(dict(guid_hex=self.data[off:off+16].hex()))
        if address in [0x141597e01,0x141597e0c]:
            value=uc.reg_read(x.UC_X86_REG_EAX);self.version_calls[-1]['result']=value if value<0x80000000 else value-0x100000000
        if address==0x1468e4100:
            length=uc.reg_read(x.UC_X86_REG_RCX)
            if length not in [8,16] or len(self.allocations)>=4:raise ValueError('Structured archive allocation bound')
            pointer=self.base+0xa000+len(self.allocations)*0x100
            uc.mem_write(pointer,bytes(length));self.allocations.append(dict(size=length,pointer=pointer));self.native_return(pointer);return
        if address==0x141422070:
            state=struct.unpack('<Q',uc.mem_read(self.obj+0x248,8))[0];cursor,end=struct.unpack('<QQ',uc.mem_read(state,16));offset=cursor-self.inputs[0]
            if not 0<=offset<=self.lengths[0]-4:raise ValueError('Actor FString length bound')
            length=struct.unpack_from('<i',self.actor_raw,offset)[0]
            if not 1<=length<=4096 or cursor+4+length>end:raise ValueError('Actor FString data bound')
            b=self.actor_raw[offset+4:offset+4+length]
            if len(b)!=length or b[-1]!=0 or b'\0' in b[:-1]:raise ValueError('Actor FString terminator')
            self.strings.append(dict(begin=offset,end=offset+4+length,value=b[:-1].decode('ascii')))
            uc.mem_write(state,struct.pack('<Q',cursor+4+length));out=uc.reg_read(x.UC_X86_REG_RDX)
            if not self.base<=out<out+16<=self.base+0x40000:raise ValueError('Actor FString output bound')
            uc.mem_write(out,bytes(16));self.native_return();return
        super().guard(uc,address,size,_)

    def execute(self,address,registers,stop=None):
        uc=self.uc;x=self.x;self.stop=None;rsp=self.base+0x3f008
        uc.mem_write(rsp,struct.pack('<Q',self.base));uc.reg_write(x.UC_X86_REG_RSP,rsp)
        for reg,value in registers:uc.reg_write(reg,value)
        uc.emu_start(address,self.base,count=20000)
        if stop is not None:
            if self.stop!=stop:raise ValueError('Unexpected initializer stop '+str(self.stop))
        elif uc.reg_read(x.UC_X86_REG_RIP)!=self.base:raise ValueError('Initializer instruction bound')

    def flags(self,initial):
        self.setup((170,8),True);uc=self.uc;x=self.x;archive=self.obj+0x240
        uc.mem_write(archive+0x28,struct.pack('<H',initial))
        self.execute(0x14173c4cd,[(x.UC_X86_REG_RDI,archive)],0x14173c4e9)
        actual=struct.unpack('<H',uc.mem_read(archive+0x28,2))[0]
        if actual!=initial|0x101:raise ValueError('Loading/string flag initialization mismatch')
        return dict(initial_flag_word=initial,result_flag_word=actual)

    def chain(self,actor_raw,package_flags):
        self.setup((170,8),True);self.allocations=[];self.strings=[];self.version_calls=[];self.actor_raw=actor_raw
        uc=self.uc;x=self.x;archive=self.obj+0x240
        # Source version rows are from the pinned registration evidence. The
        # FArchive constructor's zero flag state is supplied before native init.
        self.execute(0x14173eb10,[(x.UC_X86_REG_RCX,self.obj),(x.UC_X86_REG_RDX,self.reader),(x.UC_X86_REG_R8,1)])
        first_structured=struct.unpack('<Q',uc.mem_read(self.obj+0x2f0,8))[0]
        self.execute(0x141599f90,[(x.UC_X86_REG_RCX,self.obj+0x2f8)])
        adapter_result=uc.reg_read(x.UC_X86_REG_RAX)
        if adapter_result!=archive:raise ValueError('Structured adapter archive mismatch')
        # Rebinding retains the structured archive object, replacing only slot8.
        self.execute(0x14173eb10,[(x.UC_X86_REG_RCX,self.obj),(x.UC_X86_REG_RDX,self.reader),(x.UC_X86_REG_R8,0)])
        if struct.unpack('<Q',uc.mem_read(self.obj+0x2f0,8))[0]!=first_structured:raise ValueError('Structured archive not retained')
        self.execute(0x141599f90,[(x.UC_X86_REG_RCX,self.obj+0x2f8)])
        if uc.reg_read(x.UC_X86_REG_RAX)!=archive:raise ValueError('Rebound adapter archive mismatch')
        self.execute(0x14173c4cd,[(x.UC_X86_REG_RDI,archive)],0x14173c4e9)
        self.execute(0x14159ca30,[(x.UC_X86_REG_RCX,archive)])
        after_init=bytes(uc.mem_read(archive+0x28,2)).hex()
        uc.mem_write(self.obj+0xc8,struct.pack('<I',package_flags))
        self.execute(0x14173dc3e,[(x.UC_X86_REG_RSI,self.obj)],0x14173dcaa)
        after_package=bytes(uc.mem_read(archive+0x28,2)).hex()
        self.execute(0x14173fa73,[(x.UC_X86_REG_RDI,self.obj)],0x14173fb41)
        after_versions=bytes(uc.mem_read(archive+0x28,4)).hex()
        state=self.base+0xb000;self.lengths[0]=len(actor_raw);uc.mem_write(self.inputs[0],actor_raw)
        uc.mem_write(archive+8,struct.pack('<Q',state));uc.mem_write(state,struct.pack('<QQ',self.inputs[0]+375,self.inputs[0]+len(actor_raw)))
        actor=self.base+0x8000;slot=struct.unpack('<Q',uc.mem_read(self.obj+0x2f8,8))[0]
        # Execute actual optional-GUID entry, including native adapter and flags.
        self.execute(0x14173a560,[(x.UC_X86_REG_RCX,actor),(x.UC_X86_REG_RDX,slot)],0x14173a9e2)
        optional_end=struct.unpack('<Q',uc.mem_read(state,8))[0]-self.inputs[0]
        self.execute(0x14381b317,[(x.UC_X86_REG_RBX,archive),(x.UC_X86_REG_RDI,actor)],0x144351d5d)
        end=struct.unpack('<Q',uc.mem_read(state,8))[0]-self.inputs[0]
        rsp=uc.reg_read(x.UC_X86_REG_RSP);words=list(struct.unpack('<8I',uc.mem_read(rsp+0x30,32)))
        if after_init!='0101' or after_package!='4301' or after_versions!='43018010' or optional_end!=379 or end!=443:raise ValueError('Composed actor tail cursor/flag mismatch')
        if [r.get('result') for r in self.version_calls]!=[8,170]:raise ValueError('Composed custom-version return mismatch')
        if words!=list(struct.unpack_from('<8I',actor_raw,411)):raise ValueError('Native composed actor GUID mismatch')
        return dict(structured_allocations=self.allocations,adapter_returns_embedded=True,rebind_preserves_structured=True,
            flags_after_initialization_hex=after_init,flags_after_package_hex=after_package,
            flag_bytes_after_versions_hex=after_versions,native_custom_version_calls=self.version_calls,
            optional_guid_end=optional_end,actor_tail_end=end,actor_string=self.strings,guid_words=words,
            version_lookup_substituted=False,property_end_input=375,property_serializer_executed=False,
            bounded_copy_reserve_substitutions=self.substituted_calls)

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    source_paths=['code-clues/recast-archive-transfer.json','code-clues/recast-archive-defaults.json','code-clues/recast-actor-properties.json']
    inputs={};sources={}
    for p in source_paths:
        b=(root/p).read_bytes();inputs[p]=sha(b);sources[p]=json.loads(b)
    vm=InitializationReplay(root);source=sources[source_paths[0]];assert sha(vm.data)==source['sha256']
    property_report=sources[source_paths[2]];entry=property_report['actor_export'];actor=(root/'maps/navigation-study/level'/entry['file']).read_bytes()
    assert sha(actor)==entry['export']['sha256'] and property_report['decoded']['properties_end']==375
    cases=[vm.flags(value) for value in [0,0xffff,0xfefe,0x40]]
    chain=vm.chain(actor,source['package_flags']['value'])
    rows={r['address']:r for f in vm.fragments for r in f['instructions']}
    addresses=[0x1417345cb,0x141734e29,0x14173c4d0,0x14173c4d5,0x14173c4de,0x14173c4e3,0x14173c4f9,
        0x14173eb29,0x14173eb59,0x14173eb85,0x14173a579,0x14173a581,0x14381b317,0x14381b32b,0x14381b3f2,
        0x14159350f,0x141593582,0x14173fad6,0x14173fade,0x14173fae1]
    report=dict(source=source['source'],sha256=sha(vm.data),builder_sha256=sha(Path(__file__).read_bytes()),source_report_sha256=inputs,
        source_helper_sha256={p:sha((HERE/p).read_bytes()) for p in ['build-recast-archive-transfer.py','recast-portal-emulator.py']},
        fragments=vm.fragments,anchors=[rows[a] for a in addresses],initialization_bindings=vm.initialization_bindings,
        initialization_leaves=vm.initialization_leaves,native_flag_cases=cases,native_composed_chain=chain,pages=list(vm.pages.values()),
        actor_export=entry,summary=dict(native_flag_cases=4,structured_adapter_replays=2,
            loading_and_actor_string_flags_from_native_initializer=True,tail_with_native_initialized_flags_end=443,
            native_tail_custom_version_lookup=True,full_property_boundary_verified=False,active_mesh_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['Flags replay begins at the initializer flag block, skipping preceding scalar/engine-version setup.',
            'Native structured binding uses bounded16/8byte allocation; rebind behavior is tested; reader factory remains unresolved.',
            'Version registry rows170/8 and source properties-end375 are pinned prior evidence, not a full process/global registry/schema execution.',
            'FString ANSI load is substituted without native allocation/conversion; actor replay stops before GUID registry writes.',
            'Full preload gates, property schema/alignment, active tile selection and character traversal remain unverified.'])
    path=root/'code-clues/recast-archive-initialization.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()))));return report
if __name__=='__main__':main()
