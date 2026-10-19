"""Execute CharacterListReadResult and actual record readers with bounded containers."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('list_reader_base',HERE/'replay-login-result-reader.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
CTOR,READER,TABLE=0x1456d47a0,0x1456d8d80,0x1498d8540
RECORD_CTOR,RECORD_READER,RECORD_TABLE=0x14577d3d0,0x145781c80,0x1498d7ff8


def record_bytes(text='',value=0,enum=0,appearance_enum=0,flag=0):
    """Explicit fixture wire sequence; nested arrays empty and optional absent."""
    encoded=text.encode('utf-8');s=struct.pack('<H',len(encoded))+encoded
    q=struct.pack('<Q',value);i=struct.pack('<I',value & 0xffffffff)
    appearance=bytes([appearance_enum])+bytes(range(9))+s+bytes([flag,255])+b'\0\0'
    return q+i+s+q+i+q+q+s+bytes([enum])+q+q+q+q+q+q+appearance+q+q+q+bytes([flag,0])


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        addresses=(READER,RECORD_CTOR,RECORD_READER,0x1456da1a0,0x1456e3ea0,
            0x144aa5c50,0x1457812a0,0x1456bf640,0x14578dfa0,0x1456b60e0)
        self.list_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in addresses})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.list_fragments)
        self.list_leaves=[]
        cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
        for a in (CTOR,0x145789700):
            off=self.image.offset(a-self.image.pe.base);rows=[]
            for ins in cs.disasm(self.raw[off:off+128],a):
                rows.append(ins)
                if ins.mnemonic=='ret':break
                if ins.mnemonic not in ('mov','lea','xor'):raise ValueError('Unreviewed list constructor leaf')
            if not rows or rows[-1].mnemonic!='ret':raise ValueError('List constructor leaf bound')
            size=rows[-1].address+rows[-1].size-a
            self.list_leaves.append(dict(address=a,file_offset=off,bytes=self.raw[off:off+size].hex()))
            self.ranges.append((a,a+size))
        self.list_hooks={0x1456d32e0,0x1420e2ac0,0x1456d4870,0x14577ef70,0x1456b1640}
        refs=[a for f in self.list_fragments for r in f['instructions'] for a in r['rip_references']]
        pages={p for lo,hi in self.ranges for p in range(lo & ~4095,(hi+4095)&~4095,4096)}
        pages.update(a & ~4095 for a in (*refs,*self.list_hooks,TABLE,RECORD_TABLE,0x1498d90a0,0x1498d0460))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])

    def finish(self,result):
        self.uc.reg_write(x.UC_X86_REG_RAX,result)
        sp=self.uc.reg_read(x.UC_X86_REG_RSP)
        self.uc.reg_write(x.UC_X86_REG_RIP,int.from_bytes(self.uc.mem_read(sp,8),'little'))
        self.uc.reg_write(x.UC_X86_REG_RSP,sp+8)

    def hook(self,uc,address,size,user):
        if address not in self.list_hooks:return super().hook(uc,address,size,user)
        a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
        result=uc.reg_read(x.UC_X86_REG_RAX)
        if address==0x1420e2ac0:
            if b>4:raise ValueError('Native list fixture count bound')
            pointer=self.alloc(b*0x170) if b else 0
            uc.mem_write(a,struct.pack('<Q',pointer));uc.mem_write(a+12,struct.pack('<I',b))
        elif address==0x1456d4870:
            if not self.scratch<=a<=self.scratch+0x28000-0x170:raise ValueError('Record copy fixture bound')
            uc.mem_write(a,bytes(uc.mem_read(b,0x170)));result=a
        # Cleanup captures preserve RAX; no native allocation lifetime proof.
        self.finish(result)

    def read_list(self,data):
        if len(data)>4096:raise ValueError('List fixture byte bound')
        self.heap=self.scratch+0x10000;self.copy_sizes=[];self.io_entries=[]
        packet,archive,buffer=self.scratch+0x1000,self.scratch+0x2000,self.scratch+0x8000
        self.uc.mem_write(packet,bytes(0x400));self.uc.mem_write(buffer,bytes(4096));self.uc.mem_write(buffer,data)
        self.call(CTOR,packet);self.call(0x144aa6260,archive,buffer,len(data),1,0)
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000
        self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,packet),(x.UC_X86_REG_RDX,archive)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(READER,stop,count=250000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('List reader instruction budget')
        pointer,count,capacity=struct.unpack('<QII',bytes(self.uc.mem_read(packet+0x18,16)))
        if not 0<=count<=capacity<=4:raise ValueError('Native list result fixture bound')
        records=[]
        for index in range(count):
            record=pointer+index*0x170
            strings=[]
            for offset in (0x18,0x50,0xc8):
                p,n,cap=struct.unpack('<QII',bytes(self.uc.mem_read(record+offset,16)))
                if not 0<=n<=cap<=1024:raise ValueError('Record string fixture bound')
                strings.append(bytes(self.uc.mem_read(p,(n-1)*2)).decode('utf-16le') if n else '')
            records.append(dict(strings=strings,
                u32=[int.from_bytes(self.uc.mem_read(record+o,4),'little') for o in (0x10,0x30)],
                u16=[int.from_bytes(self.uc.mem_read(record+o,2),'little') for o in (0x70,0x72,0x74,0x76)],
                u64=[int.from_bytes(self.uc.mem_read(record+o,8),'little') for o in
                    (8,0x28,0x40,0x48,0x80,0x88,0x98,0xa0,0xa8,0xf0,0xf8,0x100)],
                enum60=int.from_bytes(self.uc.mem_read(record+0x60,1),'little'),
                appearance=list(self.uc.mem_read(record+0xb8,10)),
                appearance_flags=list(self.uc.mem_read(record+0xd8,2)),
                flag108=int.from_bytes(self.uc.mem_read(record+0x108,1),'little'),
                optional=int.from_bytes(self.uc.mem_read(record+0x118,1),'little')))
        return dict(payload_hex=data.hex(),returned=self.uc.reg_read(x.UC_X86_REG_AL),records=records,
            consumed=int.from_bytes(self.uc.mem_read(archive+0x30,8),'little')-buffer,
            raw10=int.from_bytes(self.uc.mem_read(packet+0x10,4),'little'),
            raw14=int.from_bytes(self.uc.mem_read(packet+0x14,4),'little'),count=count,
            tail=[int.from_bytes(self.uc.mem_read(packet+o,s),'little') for o,s in ((0x28,8),(0x30,4),(0x38,8),(0x40,8))])


def build():
    em=Emulator()
    cases=[em.read_list(struct.pack('<IIHQIQQ',a,b,0,c,d,e,f)) for a,b,c,d,e,f in
        ((0,0,0,0,0,0),(1,207,1,207,2,3),(0xffffffff,0xffffffff,2**64-1,2**32-1,2**64-1,2**64-1))]
    data=bytes.fromhex(cases[0]['payload_hex'])
    truncated=[em.read_list(data[:n]) for n in range(len(data))]
    for text,value,enum,ae,flag in (('',0,0,0,0),('Ж界🙂',0x12345678,255,255,255),('a'*128,2**64-1,5,1,1)):
        for count in (1,2,4):
            record=record_bytes(text,value,enum,ae,flag)
            body=struct.pack('<IIH',0,207,count)+record*count+struct.pack('<QIQQ',1,2,3,4)
            c=em.read_list(body)
            if c['returned']!=1 or c['consumed']!=len(body) or c['count']!=count:
                raise ValueError('Native record list reader mismatch '+str(c))
            cases.append(c)
    one=struct.pack('<IIH',0,207,1)+record_bytes('Ж🙂',0x102030405060708,255,255,255)+struct.pack('<QIQQ',1,2,3,4)
    record_truncated=[em.read_list(one[:n]) for n in range(len(one))]
    if any(c['returned']!=0 for c in truncated+record_truncated):raise ValueError('Native truncated list unexpectedly accepted')
    trailing=em.read_list(one+b'extra')
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),fragments=em.list_fragments,
        leaves=em.list_leaves,cases=cases,truncated=truncated,record_truncated=record_truncated,
        trailing=trailing,native_execution=True,network_ready=False,
        limitations=['Actual list constructor/reader/array dispatcher/scalar archive IO execute.',
            'Bounded container allocation/copy/cleanup fixtures; no native allocation lifetime proof.',
            'Record appearance extension array empty and optional extension absent; nonempty extensions unverified.',
            'No handler/network/real response/account session/game process/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-list-reader-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
