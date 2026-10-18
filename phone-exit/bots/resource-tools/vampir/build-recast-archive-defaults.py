"""Recover registered versions and package-summary default selection from EXE.

No global registry/OS call is executed. Native initializers run to registration;
the package gate runs to the global-version snapshot call. Archive propagation,
wrapper flags and live activation remain separate unverified requirements.
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
tail=load('archive_defaults_tail','decode-recast-actor-tail.py')

def package_prefix(raw):
    if len(raw)<32:raise ValueError('Truncated package prefix')
    tag,legacy,discarded,ue4,ue5,licensee,count,header_size=struct.unpack_from('<I7i',raw)
    if tag!=0x9e2a83c1 or legacy!=-8 or count!=0 or not 32<=header_size<=len(raw):raise ValueError('Unsupported package prefix')
    return dict(legacy=legacy,discarded_legacy_ue3=discarded,ue4=ue4,ue5=ue5,licensee=licensee,
        serialized_custom_version_count=count,header_size=header_size,select_registered_defaults=not any([ue4,ue5,licensee]))

class DefaultsReplay(tail.TailReplay):
    def __init__(self,root):
        super().__init__(root)
        native=load('archive_defaults_native','build-native-entry-code.py')
        self.fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in
            [0x140ff4ae0,0x140ff52b0,0x14159bf30,0x141599e50,0x141599fa0,0x14175fa90]})
        self.allowed=[(self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.fragments]

    def read_image(self,pointer,size):
        for page in range(pointer&~4095,(pointer+size+4095)&~4095,4096):
            if page not in self.pages:self.map_page(self.uc,self.u.UC_MEM_READ_UNMAPPED,page,1,0,None)
        return bytes(self.uc.mem_read(pointer,size))

    def guard(self,uc,address,size,_):
        if address in [0x14159bf30,0x14175fcb5,0x14175fdad]:
            self.stop=address;uc.emu_stop();return
        if not any(lo<=address<hi for lo,hi in self.allowed):raise ValueError('Unexpected default-version code '+hex(address))

    def registration(self,address):
        uc=self.uc;x=self.x;self.stop=None
        uc.reg_write(x.UC_X86_REG_RSP,self.base+0x3f008)
        uc.emu_start(address,self.base,count=100)
        if self.stop!=0x14159bf30:raise ValueError('Registration call not reached')
        name_ptr=uc.reg_read(x.UC_X86_REG_R8);name_raw=self.read_image(name_ptr,128)
        # Search UTF-16 terminator on code-unit boundaries.
        end=next(i for i in range(0,128,2) if name_raw[i:i+2]==b'\0\0');name_raw=name_raw[:end+2]
        return dict(initializer=address,guid_hex=bytes(uc.mem_read(uc.reg_read(x.UC_X86_REG_RCX),16)).hex(),
            version=uc.reg_read(x.UC_X86_REG_EDX),name=name_raw[:-2].decode('utf-16le'),
            name_address=name_ptr,name_file_offset=self.image.offset(name_ptr-self.image.pe.base),name_raw_hex=name_raw.hex(),
            callback=uc.reg_read(x.UC_X86_REG_R9),stop_address=self.stop)

    def package_gate(self,values):
        uc=self.uc;x=self.x;summary=self.base+0x6000;self.stop=None
        uc.mem_write(summary,bytes(256));uc.mem_write(summary+4,struct.pack('<3i',*values))
        for reg,value in [(x.UC_X86_REG_RSP,self.base+0x3f000),(x.UC_X86_REG_RBP,self.base+0x3f100),
            (x.UC_X86_REG_RSI,summary),(x.UC_X86_REG_RDI,summary+8),(x.UC_X86_REG_R14,summary+12),
            (x.UC_X86_REG_R15,summary+4),(x.UC_X86_REG_R13,0)]:uc.reg_write(reg,value)
        uc.emu_start(0x14175fc7b,self.base,count=100)
        if self.stop not in [0x14175fcb5,0x14175fdad]:raise ValueError('Summary gate stop not reached')
        return dict(input_versions=list(values),stop_address=self.stop,defaults_selected=self.stop==0x14175fcb5,
            summary_unversioned_byte=uc.mem_read(summary+0xf0,1)[0],
            effective_scalar_versions=list(struct.unpack('<3i',uc.mem_read(summary+4,12))))

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    vm=DefaultsReplay(root);registrations=[vm.registration(a) for a in [0x140ff4ae0,0x140ff52b0]]
    assert [(r['name'],r['version']) for r in registrations]==[('FortniteMain',170),('UE5-PrivateFrosty',8)]
    for row in registrations:
        matches=[]
        for sec in vm.image.pe.sections:
            if sec['name']!='.rdata':continue
            raw=vm.data[sec['raw']:sec['raw']+sec['raw_size']];needle=struct.pack('<Q',row['initializer']);pos=raw.find(needle)
            while pos!=-1:
                matches.append(dict(address=vm.image.pe.base+sec['rva']+pos,file_offset=sec['raw']+pos,raw_hex=needle.hex()));pos=raw.find(needle,pos+1)
        assert len(matches)==1;row['initializer_pointer_records']=matches
    folder=root/'maps/navigation-study/level';asset=(folder/'Nocturne-asset.bin').read_bytes();prefix=package_prefix(asset)
    generated_folder=root/'maps/navigation-study/generated-chunks';generated_raw=(generated_folder/'index.json').read_bytes();generated=json.loads(generated_raw)
    generated_prefixes=[]
    for package in generated['packages']:
        if not any(e['export']['type']=='RecastNavMeshDataChunk' for e in package['navigation_exports']):continue
        part=next(p for p in package['parts'] if p['role']=='asset');b=(generated_folder/part['file']).read_bytes();assert sha(b)==part['sha256']
        decoded=package_prefix(b);assert decoded['select_registered_defaults']
        generated_prefixes.append(dict(package=package['package_identity'],file=part['file'],sha256=sha(b),prefix_hex=b[:32].hex(),decoded=decoded))
    cases=[vm.package_gate(v) for v in [(prefix['ue4'],prefix['ue5'],prefix['licensee']),(1,0,0),(0,1,0),(0,0,1)]]
    assert [c['defaults_selected'] for c in cases]==[True,False,False,False]
    assert cases[0]['effective_scalar_versions']==[522,1013,0]
    properties_raw=(root/'code-clues/recast-actor-properties.json').read_bytes();properties=json.loads(properties_raw)
    actor=(folder/properties['actor_export']['file']).read_bytes();assert sha(actor)==properties['actor_export']['export']['sha256']
    values={r['guid_hex']:r['version'] for r in registrations};lv=values['525dda5948493212785978b88be9b870'];gv=values['86181d60844f64acded316aad6c7ea0d']
    replay=tail.TailReplay(root).replay(actor,379,lv,gv);assert replay['end']==443
    rows={r['address']:r for f in vm.fragments for r in f['instructions']}
    anchor_addresses=[0x140ff4ae4,0x140ff4af5,0x140ff4b04,0x140ff52b4,0x140ff52cf,0x140ff52d3,
        0x14175fc7b,0x14175fc85,0x14175fc8e,0x14175fc97,0x14175fcb5,0x141599e62,0x141599e8a,0x141599ecc,
        0x141599fd7,0x141599fe4,0x14159a004,0x14159a028,0x14159a02c,0x14159a067,0x14159a0cf]
    report=dict(source=str(json.loads((root/'code-clues/native-enums.json').read_bytes())['source']),sha256=sha(vm.data),
        builder_sha256=sha(Path(__file__).read_bytes()),source_properties_sha256=sha(properties_raw),
        fragments=vm.fragments,anchors=[rows[a] for a in anchor_addresses],pages=list(vm.pages.values()),
        registrations=registrations,asset_file='maps/navigation-study/level/Nocturne-asset.bin',asset_sha256=sha(asset),
        package_prefix_hex=asset[:32].hex(),package_prefix=prefix,native_summary_gate_cases=cases,
        generated_index_sha256=sha(generated_raw),generated_package_prefixes=generated_prefixes,
        actor_tail_with_registered_versions=replay,
        summary=dict(registered_tile_key_version=gv,registered_actor_string_key_version=lv,
            unversioned_package_selects_registered_snapshot=True,registered_version_actor_tail_end=443,
            generated_packages_selecting_defaults=len(generated_prefixes),
            runtime_archive_propagation_verified=False,full_property_boundary_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['Initializers stop at registration call; global map insertion/CRT execution are not emulated.',
            'Package gate starts after scalar version decoding; default snapshot call is reached but not executed.',
            'Snapshot copy/refresh and lazy loading-archive defaults are pinned static code, not full registry execution.',
            'Actual package-to-export archive propagation and flags still require tracing; native tail replay retains explicit synthetic flags.',
            'Registered170 is stronger than arbitrary97, but tile extraction remains a conditional replay until archive propagation/property schemas are verified.'])
    path=root/'code-clues/recast-archive-defaults.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()))));return report
if __name__=='__main__':main()
