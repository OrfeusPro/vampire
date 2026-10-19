"""Native state-key hash lookup and label access, without inventing live records."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('state_lookup_base',HERE/'replay-selection-state-transition.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
LOOKUP,HASH,ACCESSOR,LABEL=0x145c5d860,0x145c60180,0x141482990,0x145dc3f30
RECORD_LABEL=0x30005000


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.lookup_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(LOOKUP)]})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.lookup_fragments)
        self.lookup_leaves=[]
        for a,length in ((HASH,0x76),(ACCESSOR,5)):
            off=self.image.offset(a-self.image.pe.base);data=self.raw[off:off+length]
            self.lookup_leaves.append(dict(address=a,file_offset=off,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest()))
            self.ranges.append((a,a+length))
        self.lookup_hooks={0x145c38ab0,RECORD_LABEL}
        pages={p for begin,end in self.ranges for p in range(begin & ~4095,(end+4095) & ~4095,4096)}
        pages.update(a & ~4095 for a in self.lookup_hooks)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])

    def hook(self,uc,address,size,user):
        # These were fixtures in the preceding replay; now execute real code.
        if address in (LOOKUP,ACCESSOR):return
        if address in self.lookup_hooks:
            if address==0x145c38ab0:
                self.finish(self.registry);return
            this=uc.reg_read(x.UC_X86_REG_RCX)
            if this not in self.records:raise ValueError('Unexpected selected registry record')
            self.label_reads.append(self.records[this])
            self.finish(self.ctx+0xe000);return
        super().hook(uc,address,size,user)

    def execute_lookup(self,fixture):
        self.heap=self.scratch+0x10000;self.events=[];self.label_reads=[]
        self.fixture=dict(label_text='registry-label-fixture',label_present=True)
        self.registry=self.ctx+0x1000
        self.uc.mem_write(self.ctx,bytes(0x10000))
        entries,buckets,table=self.ctx+0x2000,self.ctx+0x4000,self.ctx+0x5000
        self.records={}
        for index,key in enumerate(fixture['keys']):
            record=entries+index*0x150
            self.uc.mem_write(record,struct.pack('<I',key))
            self.uc.mem_write(record+8,struct.pack('<Q',table))
            self.uc.mem_write(record+0x148,struct.pack('<i',index+1 if index+1<len(fixture['keys']) else -1))
            self.records[record+8]=key
        self.uc.mem_write(table+0x20,struct.pack('<Q',RECORD_LABEL))
        self.fwrite(self.ctx+0xe000,'registry-label-fixture')
        self.uc.mem_write(self.registry+0x18,struct.pack('<Q',entries))
        self.uc.mem_write(self.registry+0x20,struct.pack('<I',len(fixture['keys'])))
        self.uc.mem_write(self.registry+0x4c,struct.pack('<I',fixture['free_count']))
        self.uc.mem_write(self.registry+0x60,struct.pack('<I',fixture['bucket_count']))
        self.uc.mem_write(self.registry+0x50,b'\xff'*8)
        self.uc.mem_write(buckets,b'\xff'*32)
        pointer=buckets if fixture['external'] else self.registry+0x50
        self.uc.mem_write(self.registry+0x58,struct.pack('<Q',buckets if fixture['external'] else 0))
        if fixture['keys'] and not fixture['empty_bucket']:
            bucket=fixture['query'] & (fixture['bucket_count']-1)
            self.uc.mem_write(pointer+bucket*4,struct.pack('<i',0))
        descriptor=self.scratch+0x3000
        self.run(LOOKUP,descriptor,fixture['query'])
        key=int.from_bytes(self.uc.mem_read(descriptor,4),'little')
        raw_pointer=int.from_bytes(self.uc.mem_read(descriptor+8,8),'little')
        self.run(ACCESSOR,descriptor)
        if self.uc.reg_read(x.UC_X86_REG_RAX)!=raw_pointer:raise ValueError('Registry descriptor accessor changed')
        expected_key=fixture['query'] if raw_pointer else None
        selected=self.records.get(raw_pointer)
        if selected!=expected_key:raise ValueError('Registry matched wrong fixture record')
        output=self.scratch+0x4000
        # LABEL is a three-argument function; set R8 explicitly.
        self.uc.reg_write(x.UC_X86_REG_R8,fixture['query'])
        self.run(LABEL,0,output)
        label=self.fread(output)
        return dict(fixture=fixture,descriptor_key=key,selected_key=selected,
            pointer_offset=None if not raw_pointer else raw_pointer-entries,label=label,label_reads=self.label_reads.copy())


def build():
    path=native.ROOT/'code-clues/selection-state-transition-replay.json';prior=json.loads(path.read_text('utf-8'))
    em=Emulator()
    if prior['sha256']!=em.bindings['sha256']:raise ValueError('State lookup source mismatch')
    default=dict(query=2,keys=[2],free_count=0,bucket_count=1,external=False,empty_bucket=False)
    fixtures=[dict(default,name='inline-hit'),dict(default,name='inline-miss',keys=[3]),
        dict(default,name='empty',keys=[]),dict(default,name='all-free',free_count=1),
        dict(default,name='bucket-empty',empty_bucket=True),dict(default,name='external-hit',bucket_count=4,external=True),
        dict(default,name='collision-hit',keys=[6,10,2],bucket_count=4,external=True),
        dict(default,name='collision-miss',keys=[6,10],bucket_count=4,external=True)]
    fixtures.extend(dict(default,name='key-'+str(key),query=key,keys=[key]) for key in (0,1,3,255,0xffffffff))
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fragments=em.lookup_fragments,leaves=em.lookup_leaves,cases=[em.execute_lookup(f) for f in fixtures],
        native_execution=True,network_ready=False,actual_state2_label_verified=False,
        limitations=['Actual lookup/hash/descriptor accessor/state-label caller execute; registry getter and records are fixtures.',
            'Lookup returns inline record+8, not a pointer read from record; key2 semantic label remains unknown.',
            'Record virtual20/string copy are fixtures, text is not an actual map path or state name.',
            'Registry TLS initialization/static loaders exported but not executed; dynamic population provenance remains open.',
            'No world lifecycle/slot90 dispatch/network/session/game/profile/process memory/credentials/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/selection-state-lookup-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
