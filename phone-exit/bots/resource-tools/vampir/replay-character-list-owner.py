"""Bind the actual owner constructor/vtable/policy to CharacterListRead dispatch."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owner_base',HERE/'replay-character-list-caller.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
CTOR,TABLE,POLICY=0x1468e29a0,0x149e0e7c8,0x140bb4a10


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.owner_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(CTOR)]})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.owner_fragments)
        off=self.image.offset(POLICY-self.image.pe.base)
        if self.raw[off:off+3]!=b'\xb0\x01\xc3':raise ValueError('Owner policy is no longer AL1/RET')
        self.ranges.append((POLICY,POLICY+3))
        self.owner_hooks={0x1454fc6f0,0x141430bd0}
        pages={p for lo,hi in self.ranges for p in range(lo & ~4095,(hi+4095)&~4095,4096)}
        pages.update(range(TABLE & ~4095,(TABLE+0xa20+4095)&~4095,4096))
        pages.update(a & ~4095 for a in self.owner_hooks)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])

    def hook(self,uc,address,size,user):
        if address in self.owner_hooks:
            self.events.append(dict(action='owner_constructor_helper_capture',address=address))
            self.finish(0);return
        super().hook(uc,address,size,user)

    def owner_case(self,disabled):
        self.initialize();self.object=self.service;self.events=[]
        self.uc.mem_write(self.ctx,bytes(0x10000))
        self.uc.mem_write(self.ctx+0x5000,struct.pack('<Q',self.ctx))
        self.run(CTOR,self.ctx+0x5000)
        actual_table=int.from_bytes(self.uc.mem_read(self.ctx,8),'little')
        if actual_table!=TABLE:raise ValueError('Owner constructor vtable mismatch')
        wrapper,table=self.scratch+0x6000,self.scratch+0x7000
        self.uc.mem_write(wrapper,struct.pack('<Q',table))
        self.uc.mem_write(table+0x38,struct.pack('<Q',base.base.base.SEND))
        self.uc.mem_write(0x14b520d90,struct.pack('<Q',wrapper))
        self.uc.mem_write(0x14b27eecb,bytes([disabled]))
        self.uc.mem_write(0x14b144a68,b'\0');self.uc.mem_write(0x14b571319,b'\0')
        self.run(base.CALLER,self.ctx)
        return dict(lookup_disabled=disabled,owner_vtable=actual_table,events=self.events.copy(),
            field260=int.from_bytes(self.uc.mem_read(self.ctx+0x2260,1),'little'))


def build():
    em=Emulator();anchors=[]
    for a,size in ((TABLE,0xa20),(POLICY,3)):
        off=em.image.offset(a-em.image.pe.base)
        anchors.append(dict(address=a,file_offset=off,bytes=em.raw[off:off+size].hex()))
    table=bytes.fromhex(anchors[0]['bytes'])
    for slot,target in ((0x7b0,base.CALLER),(0xa18,POLICY)):
        if struct.unpack_from('<Q',table,slot)[0]!=target:raise ValueError('Owner slot changed')
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        fragments=em.owner_fragments,anchors=anchors,cases=[em.owner_case(d) for d in (0,1)],
        native_execution=True,network_ready=False,
        limitations=['Actual owner constructor installs table; caller slot7b0 and policy slota18 execute with actual RequestA/packet constructor.',
            'Owner base constructor/member allocation, caller UI helpers, transport send and singleton owner attach are fixtures/captures.',
            'Null enabled lookup only; class name, engine slot7b0 lifecycle, actual level instance and load completion not established.',
            'No game process, memory, network, account session or Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-list-owner-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
