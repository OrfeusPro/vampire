"""Conditional actor-tail decode and bounded native branch replay.

Archive flags/versions are supplied scenarios, never recovered runtime values.
The FString call is replaced by a bounded ANSI reader; GUID words and branch
instructions execute unchanged. Stop before global actor registry side effects.
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

def decode_tail(raw,start,*,label_version,guid_version):
    pos=start;rows=[]
    def take(size,name):
        nonlocal pos
        if size<0 or pos<0 or pos+size>len(raw):raise ValueError('Truncated actor tail')
        b=raw[pos:pos+size];rows.append(dict(name=name,begin=pos,end=pos+size,raw_hex=b.hex()));pos+=size;return b
    if struct.unpack('<I',take(4,'optional_object_guid_present'))[0]!=0:raise ValueError('Present object GUID path not implemented')
    if label_version>=4:
        present=struct.unpack('<I',take(4,'actor_string_present'))[0]
        if present not in [0,1]:raise ValueError('Noncanonical boolean')
        if present:
            length=struct.unpack('<i',take(4,'actor_string_length'))[0]
            if not 1<=length<=4096:raise ValueError('Unsupported ANSI string length')
            b=take(length,'actor_string')
            if b[-1]!=0 or b'\0' in b[:-1]:raise ValueError('Invalid ANSI string')
            rows[-1]['value']=b[:-1].decode('ascii')
    if guid_version>=150:
        for label in ['actor_guid_words_1','actor_guid_words_2']:
            b=take(16,label);rows[-1]['words']=list(struct.unpack('<4I',b))
    return dict(begin=start,end=pos,records=rows,archive_inputs_verified=False)

portal=load('actor_tail_portal','recast-portal-emulator.py')

class TailReplay(portal.PortalEmulator):
    def __init__(self,root):
        super().__init__(root)
        native=load('actor_tail_native','build-native-entry-code.py')
        self.fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in [0x14381b2b0,0x141544ba0,0x144351d20,0x14173a560,0x141422070,0x141597dd0]})
        self.allowed=[(self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.fragments]
        self.archive=self.base+0x1000;self.state=self.base+0x2000
        self.uc.mem_write(self.archive+8,struct.pack('<Q',self.state))
        self.uc.mem_write(self.archive+0x28,bytes([3,1]))

    def guard(self,uc,address,size,_):
        x=self.x
        if address in [0x14381b409,0x144351d5d,0x14173a9e2,0x14173a5fe]:
            self.stop=address;uc.emu_stop();return
        if address in [0x141597dd0,0x141422070]:
            rsp=uc.reg_read(x.UC_X86_REG_RSP)
            if address==0x141597dd0:
                pointer=uc.reg_read(x.UC_X86_REG_RDX)
                if pointer&~4095 not in self.pages:self.map_page(uc,self.u.UC_MEM_READ_UNMAPPED,pointer,16,0,None)
                key=bytes(uc.mem_read(pointer,16)).hex()
                if key not in self.versions:raise ValueError('Unexpected version GUID')
                value=self.versions[key];uc.reg_write(x.UC_X86_REG_RAX,value&0xffffffff)
                self.lookups.append(dict(guid_hex=key,scenario_version=value))
            else:
                cursor=struct.unpack('<Q',uc.mem_read(self.state,8))[0];offset=cursor-self.inputs[0]
                if offset+4>self.lengths[0]:raise ValueError('String length read bound')
                length=struct.unpack_from('<i',self.raw,offset)[0]
                if not 1<=length<=4096 or offset+4+length>self.lengths[0]:raise ValueError('String data bound')
                b=self.raw[offset+4:offset+4+length]
                if b[-1]!=0 or b'\0' in b[:-1]:raise ValueError('Bad string')
                self.string=dict(begin=offset,end=offset+4+length,value=b[:-1].decode('ascii'))
                uc.mem_write(self.state,struct.pack('<Q',cursor+4+length))
                # Caller sees an empty allocation: no allocator/free/global calls.
                uc.mem_write(uc.reg_read(x.UC_X86_REG_RDX),bytes(16))
            ret=struct.unpack('<Q',uc.mem_read(rsp,8))[0]
            uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,ret);return
        if not any(lo<=address<hi for lo,hi in self.allowed):raise ValueError('Unexpected tail code '+hex(address))

    def replay(self,raw,start,label_version,guid_version):
        self.raw=raw;self.lengths[0]=len(raw);self.uc.mem_write(self.inputs[0],raw)
        self.uc.mem_write(self.state,struct.pack('<QQ',self.inputs[0]+start,self.inputs[0]+len(raw)))
        self.versions={'525dda5948493212785978b88be9b870':label_version,'86181d60844f64acded316aad6c7ea0d':guid_version}
        self.lookups=[];self.string=None;self.stop=None
        x=self.x;uc=self.uc
        for reg,value in [(x.UC_X86_REG_RSP,self.base+0x3f000),(x.UC_X86_REG_RBX,self.archive),(x.UC_X86_REG_RDI,self.base+0x3000)]:uc.reg_write(reg,value)
        uc.emu_start(0x14381b317,self.base,count=10000)
        if self.stop not in [0x14381b409,0x144351d5d]:raise ValueError('Tail did not reach bounded stop')
        end=struct.unpack('<Q',uc.mem_read(self.state,8))[0]-self.inputs[0]
        words=None
        if self.stop==0x144351d5d:
            rsp=uc.reg_read(x.UC_X86_REG_RSP);words=list(struct.unpack('<8I',uc.mem_read(rsp+0x30,32)))
        return dict(label_version=label_version,guid_version=guid_version,start=start,end=end,stop_address=self.stop,
            lookups=self.lookups,string=self.string,guid_words=words)

    def optional_absent(self,raw,start):
        self.lengths[0]=len(raw);self.uc.mem_write(self.inputs[0],raw)
        self.uc.mem_write(self.state,struct.pack('<QQ',self.inputs[0]+start,self.inputs[0]+len(raw)))
        self.stop=None;x=self.x
        self.uc.reg_write(x.UC_X86_REG_RDI,self.archive);self.uc.reg_write(x.UC_X86_REG_RSI,0)
        self.uc.emu_start(0x14173a5ad,self.base,count=100)
        if self.stop!=0x14173a9e2:raise ValueError('Optional GUID is not absent')
        return struct.unpack('<Q',self.uc.mem_read(self.state,8))[0]-self.inputs[0]

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    properties_raw=(root/'code-clues/recast-actor-properties.json').read_bytes();properties=json.loads(properties_raw)
    folder=root/'maps/navigation-study/level';entry=properties['actor_export'];raw=(folder/entry['file']).read_bytes()
    assert sha(raw)==entry['export']['sha256'];start=properties['decoded']['properties_end']
    vm=TailReplay(root);optional_end=vm.optional_absent(raw,start);assert optional_end==start+4
    rows={r['address']:r for f in vm.fragments for r in f['instructions']}
    anchors=[]
    for address,mnemonic,operands in [(0x14381b330,'cmp','eax, 4'),(0x14381b3f7,'cmp','eax, 0x96'),
        (0x14381b3be,'call','0x141422070'),(0x14381b404,'call','0x144351d20'),
        (0x144351d4b,'call','0x141544ba0'),(0x144351d58,'call','0x141544ba0')]:
        r=rows[address];assert (r['mnemonic'],r['operands'])==(mnemonic,operands);anchors.append(r)
    keys=[]
    asset=(folder/'Nocturne-asset.bin').read_bytes()
    for address in [0x14381b321,0x14381b3e8]:
        r=rows[address];va=r['rip_references'][0];off=vm.image.offset(va-vm.image.pe.base);key=vm.data[off:off+16]
        keys.append(dict(instruction=r,address=va,file_offset=off,guid_hex=key.hex(),asset_occurrences=asset.count(key)))
    scenarios=[]
    for label_version,guid_version in [(4,-1),(4,97),(4,149),(4,150),(4,151),(3,97)]:
        decoded=decode_tail(raw,start,label_version=label_version,guid_version=guid_version)
        replay=vm.replay(raw,optional_end,label_version,guid_version)
        assert replay['end']==decoded['end']
        if replay['guid_words'] is not None:
            assert replay['guid_words']==[word for r in decoded['records'] if 'words' in r for word in r['words']]
        scenarios.append(dict(decoded=decoded,native=replay))
    report=dict(source=properties['source'],sha256=properties['sha256'],source_properties_sha256=sha(properties_raw),
        builder_sha256=sha(Path(__file__).read_bytes()),actor_export=entry,fragments=vm.fragments,anchors=anchors,version_keys=keys,
        package_summary_prefix_hex=asset[:32].hex(),asset_sha256=sha(asset),optional_guid_native_end=optional_end,
        scenarios=scenarios,pages=list(vm.pages.values()),
        synthetic_inputs=dict(archive_28=3,archive_29=1,archive_68_pointer=0,versions='explicit scenario values, not recovered'),
        substitutions=['Custom-version lookup returns explicit scenario input.', 'FString call uses bounded ANSI decoder; no native allocator or conversion executed.'],
        summary=dict(tail_bytes_conditionally_accounted=68,candidate_stream_offset=443,
            version_97_tail_end=411,version_150_tail_end=443,archive_versions_verified=False,
            complete_actor_serialization_executed=False,property_boundary_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['Optional GUID replay starts inside its fast-read block; wrapper/alignment not executed.',
            'Native actor replay starts after UObject return and stops before global GUID registry writes.',
            'Threshold150 uses the SAME GUID as tile decoder threshold97. Supplying97 does not select the actor GUID-pair branch.',
            'Version keys have no raw occurrences in the extracted package asset. Runtime archive versions/flags remain unknown.',
            'Two GUID-shaped values are preserved as uint32 words; gameplay role and active area remapping are not inferred.'])
    path=root/'code-clues/recast-actor-tail.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()))));return report

if __name__=='__main__':main()
