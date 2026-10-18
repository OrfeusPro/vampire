"""Pin Linker archive version/flag transfer and replay native setters/lookups.

The embedded archive vtable is constructor-bound. The optional reader uses that
same table as an explicit scenario; its real factory/wrappers remain unresolved.
Only bounded reserve/memcpy operations substitute native allocation/runtime code.
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
portal=load('archive_transfer_portal','recast-portal-emulator.py')
TABLE=0x148a13918
KEYS=['86181d60844f64acded316aad6c7ea0d','525dda5948493212785978b88be9b870']

class TransferReplay(portal.PortalEmulator):
    def __init__(self,root):
        super().__init__(root);native=load('archive_transfer_native','build-native-entry-code.py')
        roots=[0x14172b5d0,0x14173af20,0x14173d870,0x14173f9a0,0x1415a0140,0x141594d70,0x141599fa0,0x141597dd0,0x14159a480,0x14173a9f0,0x1454d0020]
        self.fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in roots})
        self.allowed=[(self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.fragments]
        self.bindings=[];self.leaves=[]
        decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
        for slot in [0x58,0x60,0xb8,0xe0,0xf8,0x100,0x108]:
            off=self.image.offset(TABLE+slot-self.image.pe.base);target=struct.unpack_from('<Q',self.data,off)[0]
            self.bindings.append(dict(table=TABLE,slot=slot,target=target,file_offset=off,raw_hex=self.data[off:off+8].hex()))
            if self.image.containing(target) is None:
                start=self.image.offset(target-self.image.pe.base);rows=[]
                for ins in decoder.disasm(self.data[start:start+48],target):
                    if ins.mnemonic in ['call','jmp']:raise ValueError('Non-leaf archive setter')
                    rows.append(dict(address=ins.address,mnemonic=ins.mnemonic,operands=ins.op_str,bytes=bytes(ins.bytes).hex()))
                    if ins.mnemonic=='ret':break
                if not rows or rows[-1]['mnemonic']!='ret':raise ValueError('Unbounded archive setter')
                size=sum(len(bytes.fromhex(r['bytes'])) for r in rows)
                self.leaves.append(dict(address=target,file_offset=start,raw_hex=self.data[start:start+size].hex(),instructions=rows))
                self.allowed.append((target,target+size))
        self.obj=self.base+0x1000;self.reader=self.base+0x3000;self.source_array=self.base+0x4000
        self.containers=[self.base+0x5000,self.base+0x5100];self.arrays=[self.base+0x6000,self.base+0x6100]

    def guard(self,uc,address,size,_):
        if address in [0x14173fb41,0x14173dcaa,0x1452b8ff0]:self.stop=address;uc.emu_stop();return
        if address in [0x1415337c0,0x1487a2e19]:
            x=self.x;rcx=uc.reg_read(x.UC_X86_REG_RCX);rdx=uc.reg_read(x.UC_X86_REG_RDX);r8=uc.reg_read(x.UC_X86_REG_R8)
            if address==0x1415337c0:
                ptr,count,capacity=struct.unpack('<Qii',uc.mem_read(rcx,16))
                if rcx not in self.containers or ptr not in self.arrays or not 0<=rdx==count<=capacity==2:raise ValueError('Reserve outside preallocated version container')
            else:
                if rcx not in self.arrays or rdx!=self.source_array or r8!=80:raise ValueError('Version memcpy bounds')
                uc.mem_write(rcx,bytes(uc.mem_read(rdx,r8)))
            self.substituted_calls.append(hex(address))
            rsp=uc.reg_read(x.UC_X86_REG_RSP);ret=struct.unpack('<Q',uc.mem_read(rsp,8))[0]
            uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,ret);return
        if not any(lo<=address<hi for lo,hi in self.allowed):raise ValueError('Unexpected archive transfer code '+hex(address))

    def setup(self,versions,reader_present):
        uc=self.uc
        uc.mem_write(self.obj,bytes(0x1800));uc.mem_write(self.reader,bytes(0x1000));self.substituted_calls=[]
        source=b''.join(bytes.fromhex(key)+struct.pack('<i',version)+bytes(20) for key,version in zip(KEYS,versions))
        uc.mem_write(self.source_array,source);uc.mem_write(self.obj+0xb8,struct.pack('<Qii',self.source_array,2,2))
        uc.mem_write(self.obj+0xac,struct.pack('<3i',522,1013,0));uc.mem_write(self.obj+0x150,bytes.fromhex('010000000200000003000000'))
        uc.mem_write(self.obj+0x328,struct.pack('<Q',self.reader if reader_present else 0))
        for archive,container,array in zip([self.obj+0x240,self.reader],self.containers,self.arrays):
            uc.mem_write(archive,struct.pack('<Q',TABLE));uc.mem_write(archive+0x58,struct.pack('<Q',container))
            uc.mem_write(archive+0x80,b'\x01');uc.mem_write(container,struct.pack('<Qii',array,0,2));uc.mem_write(array,bytes(80))

    def run_versions(self,versions,reader_present=True):
        self.setup(versions,reader_present);uc=self.uc;x=self.x;self.stop=None
        for reg,value in [(x.UC_X86_REG_RDI,self.obj),(x.UC_X86_REG_RSP,self.base+0x3f008)]:uc.reg_write(reg,value)
        uc.emu_start(0x14173fa73,self.base,count=10000)
        if self.stop!=0x14173fb41:raise ValueError('Version transfer did not reach stop')
        result=[]
        for i,archive in enumerate([self.obj+0x240,self.reader] if reader_present else [self.obj+0x240]):
            ptr,count,capacity=struct.unpack('<Qii',uc.mem_read(self.containers[i],16))
            if count!=2 or bytes(uc.mem_read(ptr,80))!=bytes(uc.mem_read(self.source_array,80)):raise ValueError('Native version copy mismatch')
            lookups=[]
            for key in KEYS+['00'*16]:
                key_ptr=self.base+0x7000;uc.mem_write(key_ptr,bytes.fromhex(key));rsp=self.base+0x3f008;uc.mem_write(rsp,struct.pack('<Q',self.base))
                for reg,value in [(x.UC_X86_REG_RSP,rsp),(x.UC_X86_REG_RCX,archive),(x.UC_X86_REG_RDX,key_ptr)]:uc.reg_write(reg,value)
                uc.emu_start(0x141597dd0,self.base,count=10000)
                if uc.reg_read(x.UC_X86_REG_RIP)!=self.base:raise ValueError('Native lookup instruction limit')
                value=uc.reg_read(x.UC_X86_REG_EAX);value=value if value<0x80000000 else value-0x100000000;lookups.append(value)
            if lookups!=list(versions)+[-1]:raise ValueError('Transferred version lookup mismatch')
            result.append(dict(archive_role='embedded' if i==0 else 'optional_reader_synthetic_vtable',
                scalar_versions=list(struct.unpack('<3i',uc.mem_read(archive+0x40,12))),
                engine_version_raw_hex=bytes(uc.mem_read(archive+0x4c,12)).hex(),pending_default_flag=uc.mem_read(archive+0x80,1)[0],
                container_count=count,container_capacity=capacity,container_rows_hex=bytes(uc.mem_read(ptr,80)).hex(),native_lookups=lookups))
        return dict(input_versions=list(versions),reader_present=reader_present,archives=result,substituted_calls=self.substituted_calls)

    def run_flags(self,package_flags,initial_flags=1):
        self.setup((170,8),True);uc=self.uc;x=self.x;self.stop=None
        uc.mem_write(self.obj+0xc8,struct.pack('<I',package_flags))
        for archive in [self.obj+0x240,self.reader]:uc.mem_write(archive+0x28,bytes([initial_flags]))
        for reg,value in [(x.UC_X86_REG_RSI,self.obj),(x.UC_X86_REG_RSP,self.base+0x3f008)]:uc.reg_write(reg,value)
        uc.emu_start(0x14173dc3e,self.base,count=1000)
        if self.stop!=0x14173dcaa:raise ValueError('Flag transfer stop not reached')
        actual=[uc.mem_read(archive+0x28,1)[0] for archive in [self.obj+0x240,self.reader]]
        expected=(initial_flags&~0x42)|(((package_flags>>9)&1)<<1)|(((package_flags>>13)&1)<<6)
        if actual!=[expected,expected]:raise ValueError('Native package flag transfer mismatch')
        return dict(package_flags=package_flags,initial_archive_flags=initial_flags,result_archive_flags=actual,initial_loading_bit_verified=False)

    def direct_actor_dispatch(self):
        self.run_versions((170,8),True);uc=self.uc;x=self.x;actor=self.base+0x8000;tls=self.base+0x9000
        table=0x149872f38;off=self.image.offset(table+0xe0-self.image.pe.base)
        if struct.unpack_from('<Q',self.data,off)[0]!=0x1452b8ff0:raise ValueError('Changed nav actor serializer')
        uc.mem_write(actor,struct.pack('<Q',table));self.stop=None
        for reg,value in [(x.UC_X86_REG_RSI,actor),(x.UC_X86_REG_RBP,self.obj+0x240),
            (x.UC_X86_REG_R13,tls),(x.UC_X86_REG_RSP,self.base+0x3f008)]:uc.reg_write(reg,value)
        uc.emu_start(0x14173ad9a,self.base,count=100)
        if self.stop!=0x1452b8ff0:raise ValueError('Actor serializer dispatch failed')
        if uc.reg_read(x.UC_X86_REG_RCX)!=actor or uc.reg_read(x.UC_X86_REG_RDX)!=self.obj+0x240:raise ValueError('Actor archive identity mismatch')
        return dict(actor_vtable=table,slot=0xe0,target=self.stop,file_offset=off,raw_hex=self.data[off:off+8].hex(),
            passed_actor_matches=True,passed_archive_is_embedded=True,entry=0x14173ad9a,call_address=0x14173adb0,
            skipped_prior_preload_gates=True,serializer_body_executed=False)

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    defaults_raw=(root/'code-clues/recast-archive-defaults.json').read_bytes();defaults=json.loads(defaults_raw);vm=TransferReplay(root)
    assert sha(vm.data)==defaults['sha256']
    rows={r['address']:r for f in vm.fragments for r in f['instructions']}
    assert rows[0x14172b61e]['rip_references']==[TABLE] and rows[0x14172b630]['operands']=='qword ptr [r14 + 0x240], rax'
    versions=[defaults['summary']['registered_tile_key_version'],defaults['summary']['registered_actor_string_key_version']]
    cases=[vm.run_versions(versions),vm.run_versions(versions,False),vm.run_versions((149,3))]
    asset=(root/defaults['asset_file']).read_bytes();assert sha(asset)==defaults['asset_sha256']
    size=struct.unpack_from('<i',asset,32)[0];flag_offset=36+size;package_flags=struct.unpack_from('<I',asset,flag_offset)[0]
    flags=[vm.run_flags(v) for v in [package_flags,0,0x200,0x2000]]
    dispatch=vm.direct_actor_dispatch()
    assert rows[0x1454d0034]['rip_references']==[dispatch['actor_vtable']]
    forwarding_offset=vm.image.offset(0x14173cba0-vm.image.pe.base);forwarding_raw=vm.data[forwarding_offset:forwarding_offset+17]
    assert forwarding_raw.hex()=='488b89e8000000488b0148ffa070010000'
    addresses=[0x14172b606,0x14172b61e,0x14172b630,0x14173af5c,0x14173af88,0x14173d8a1,
        0x14173fa73,0x14173fa8f,0x14173fa96,0x14173faa8,0x14173faca,0x14173fb3e,
        0x1415a0150,0x1415a019f,0x1415a01a4,0x141594dce,0x14173dc5b,0x14173dc91,
        0x14173aa17,0x14173aa61,0x14173ad9e,0x14173adb0,0x1454d0034]
    report=dict(source=defaults['source'],sha256=sha(vm.data),builder_sha256=sha(Path(__file__).read_bytes()),source_defaults_sha256=sha(defaults_raw),
        fragments=vm.fragments,anchors=[rows[a] for a in addresses],vtable_bindings=vm.bindings,leaf_setters=vm.leaves,
        native_version_cases=cases,native_flag_cases=flags,native_direct_actor_dispatch=dispatch,
        read_forwarding=dict(address=0x14173cba0,file_offset=forwarding_offset,raw_hex=forwarding_raw.hex(),
            observation='embedded archive+e8 equals Linker+328 reader pointer; forwards virtual170 reads'),
        package_flags=dict(asset_sha256=sha(asset),offset=flag_offset,value=package_flags),pages=list(vm.pages.values()),
        summary=dict(embedded_archive_constructor_binding_verified=True,native_version_transfer_cases=3,native_version_lookups=15,
            native_package_flag_cases=4,embedded_versions=[170,8],package_archive_flag_byte=flags[0]['result_archive_flags'][0],
            direct_actor_receives_embedded_archive_verified=True,
            full_export_archive_chain_verified=False,full_property_boundary_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['Version replay starts after compatibility checks in Linker phase and stops before package-object updates.',
            'Embedded archive table is bound by constructor; optional reader uses the same table as an explicit scenario, real factory not identified.',
            'Containers are preallocated: reserve validates capacity and memcpy copies exactly80bounded bytes. All setter/lookup instructions execute natively.',
            'Direct actor dispatch replays the non-CDO branch after preload gates; these gates and serializer body are not executed.',
            'Initial archive loading bit1 is explicit; package flags establish only bits0x02 and0x40 here. Actor archive+29 and wrappers/alignment remain unresolved.',
            'Runtime activation, complete UObject schema and character traversal are not proved by this replay.'])
    path=root/'code-clues/recast-archive-transfer.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()))));return report
if __name__=='__main__':main()
