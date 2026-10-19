"""Native whole-list extension scenarios; container storage is an explicit fixture."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('extensions_base',HERE/'replay-character-list-reader.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x


def record_bytes(items=(),optional=None):
    record=base.record_bytes('Ж界🙂',0x102030405060708,255,255,255)
    appearance=struct.pack('<H',len(items))+b''.join(struct.pack('<IBH',*item) for item in items)
    return record[:-28]+appearance+record[-26:-1]+(b'\0' if optional is None else optional)


def list_bytes(items=(),optional=None,count=1):
    return struct.pack('<IIH',0,207,count)+record_bytes(items,optional)*count+struct.pack('<QIQQ',1,2,3,4)


def optional_bytes(entries,flag=1):
    return struct.pack('<BH',flag,len(entries))+b''.join(struct.pack('<BBIIIQ',*entry) for entry in entries)


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        addresses=(0x145737650,0x145771b40,0x1456c3890,0x1456b99b0,0x1456b7b90,0x14577dd50,0x145782b30)
        self.extension_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in addresses})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.extension_fragments)
        self.extension_leaves=[]
        cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
        for address in (0x14576f080,):
            off=self.image.offset(address-self.image.pe.base);rows=[]
            for ins in cs.disasm(self.raw[off:off+128],address):
                rows.append(ins)
                if ins.mnemonic=='ret':break
                if ins.mnemonic not in ('mov','lea','xor'):raise ValueError('Unreviewed extension leaf')
            if not rows or rows[-1].mnemonic!='ret':raise ValueError('Extension leaf bound')
            size=rows[-1].address+rows[-1].size-address
            self.extension_leaves.append(dict(address=address,file_offset=off,bytes=self.raw[off:off+size].hex()))
            self.ranges.append((address,address+size))
        self.extension_hooks={0x141417310,0x1456b2340,0x141684de0,0x1456c3fe0,
            0x1456cf6b0,0x141423ca0,0x1456d2210,0x1456cedc0,0x14577f760}
        refs=[a for f in self.extension_fragments for r in f['instructions'] for a in r['rip_references']]
        pages={p for lo,hi in self.ranges for p in range(lo & ~4095,(hi+4095)&~4095,4096)}
        pages.update(a & ~4095 for a in (*refs,*self.extension_hooks,0x1498cff58,0x1498d1a28))
        # Unicorn translates a block before invoking entry hooks; a near-page-end
        # captured helper can require the following file-backed page for decoding.
        pages.update((a & ~4095)+4096 for a in self.extension_hooks)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])

    def init_map(self,address):
        pointer=self.map_storage.get(address)
        if pointer is None:
            pointer=self.alloc(8*0x38);self.map_storage[address]=pointer
        self.uc.mem_write(address,bytes(0x50))
        self.uc.mem_write(pointer,bytes(8*0x38))
        self.uc.mem_write(address,struct.pack('<QII',pointer,0,8))
        self.uc.mem_write(address+0x2c,struct.pack('<I',128))
        self.uc.mem_write(address+0x30,struct.pack('<i',-1))
        self.uc.mem_write(address+0x38,struct.pack('<i',-1))
        self.uc.mem_write(address+0x48,struct.pack('<I',1))

    def hook(self,uc,address,size,user):
        if address not in self.extension_hooks:return super().hook(uc,address,size,user)
        a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
        result=uc.reg_read(x.UC_X86_REG_RAX)
        if address==0x141417310:
            if b>8:raise ValueError('Appearance fixture count bound')
            pointer=self.alloc(b*0x10) if b else 0
            uc.mem_write(a,struct.pack('<Q',pointer));uc.mem_write(a+12,struct.pack('<I',b))
        elif address in (0x141684de0,0x1456c3fe0):self.init_map(a)
        elif address==0x1456cf6b0:self.init_map(b)
        elif address==0x1456d2210:
            pointer,count=struct.unpack('<QI',bytes(uc.mem_read(a,12)))
            # The actual callback already searched for duplicate keys before insert.
            if any(int.from_bytes(uc.mem_read(pointer+i*0x38,1),'little')==b for i in range(count-1)):
                raise ValueError('Unexpected duplicate entered native insert')
            result=0
            self.insertions.append(b)
        elif address==0x1456cedc0:
            pointer,count=struct.unpack('<QI',bytes(uc.mem_read(a,12)))
            buckets=int.from_bytes(uc.mem_read(a+0x48,4),'little')
            if not 1<=buckets<=16 or buckets & (buckets-1):raise ValueError('Map bucket fixture bound')
            heads=[-1]*buckets
            for index in range(count):
                node=pointer+index*0x38;key=int.from_bytes(uc.mem_read(node,1),'little');bucket=key & (buckets-1)
                uc.mem_write(node+0x30,struct.pack('<iI',heads[bucket],bucket));heads[bucket]=index
            p=self.alloc(4*buckets) if buckets>1 else a+0x38
            uc.mem_write(p,struct.pack('<'+'i'*buckets,*heads))
            uc.mem_write(a+0x40,struct.pack('<Q',p if buckets>1 else 0))
        self.finish(result)

    def read_list(self,data):
        self.map_storage={};self.insertions=[]
        result=super().read_list(data)
        pointer=int.from_bytes(self.uc.mem_read(self.scratch+0x1018,8),'little')
        for index,record in enumerate(result['records']):
            addr=pointer+index*0x170
            p,n,cap=struct.unpack('<QII',bytes(self.uc.mem_read(addr+0xe0,16)))
            if not 0<=n<=cap<=8:raise ValueError('Appearance output fixture bound')
            record['appearance_items']=[[
                int.from_bytes(self.uc.mem_read(p+i*0x10+8,4),'little'),
                int.from_bytes(self.uc.mem_read(p+i*0x10+12,1),'little'),
                int.from_bytes(self.uc.mem_read(p+i*0x10+14,2),'little')] for i in range(n)]
            record['optional_items']=None
            if record['optional']:
                mp=addr+0x120;p,n=struct.unpack('<QI',bytes(self.uc.mem_read(mp,12)))
                if not 0<=n<=8:raise ValueError('Optional map output fixture bound')
                record['optional_items']=sorted([
                    [int.from_bytes(self.uc.mem_read(p+i*0x38+o,s),'little') for o,s in
                        ((0,1),(0x10,1),(0x14,4),(0x18,4),(0x1c,4),(0x28,8))] for i in range(n)])
        result['map_insertions']=self.insertions.copy()
        return result


def build():
    em=Emulator();cases=[]
    for items in ((),((0,0,0),),((0xffffffff,255,65535),(0x12345678,128,0x8001)),((1,2,3),)*8):
        for count in (1,2,4):
            body=list_bytes(items,count=count);case=em.read_list(body)
            if case['returned']!=1 or case['consumed']!=len(body):raise ValueError('Extension list native decode failed')
            if any(r['appearance_items']!=[[a,min(b,45),c] for a,b,c in items] for r in case['records']):
                raise ValueError('Appearance item native schema mismatch')
            cases.append(case)
    one=list_bytes(((0xffffffff,255,65535),(0,0,0)))
    truncated=[em.read_list(one[:n]) for n in range(len(one))]
    for entries in ((),((0,0,0,0,0,0),),((255,9,0xffffffff,0,1,0x8000000000000000),),
            ((1,255,0xffffffff,0x80000000,1,2**64-1),(9,8,1,2,3,4),(1,2,3,4,5,6)),
            tuple((i*8+1,255-i,i,0xffffffff-i,0x80000000+i,2**64-1-i) for i in range(8)),
            tuple((i*8+1,255-i,i,0xffffffff-i,0x80000000+i,2**64-1-i) for i in range(8))+((1,0,9,8,7,6),)):
        optional=optional_bytes(entries,flag=255)
        expected={e[0]:[e[0],min(e[1],9),*e[2:]] for e in entries}
        for count in (1,2,4):
            body=list_bytes(((0xffffffff,255,65535),),optional,count)
            case=em.read_list(body)
            if case['returned']!=1 or case['consumed']!=len(body):raise ValueError('Optional native list decode failed')
            if any(r['optional_items']!=sorted(expected.values()) or r['optional']!=1 for r in case['records']):
                raise ValueError('Optional native map value schema/duplicate policy mismatch '+str(case))
            if case['map_insertions']!=list(dict.fromkeys(e[0] for e in entries))*count:
                raise ValueError('Duplicate callback unexpectedly inserted another map entry')
            cases.append(case)
    optional_one=list_bytes(((1,2,3),),optional_bytes(((1,255,2,3,4,5),(9,2,3,4,5,6),(1,1,7,8,9,10)),255))
    truncated.extend(em.read_list(optional_one[:n]) for n in range(len(optional_one)))
    if any(c['returned']!=0 for c in truncated):raise ValueError('Truncated extensions accepted')
    upstream=native.ROOT/'code-clues/character-list-reader-replay.json'
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),upstream_sha256=hashlib.sha256(upstream.read_bytes()).hexdigest(),
        dependency_sha256={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-character-list-reader.py','replay-login-result-reader.py')},
        fragments=em.extension_fragments,leaves=em.extension_leaves,cases=cases,truncated=truncated,
        native_execution=True,network_ready=False,
        limitations=['Actual whole list/record/appearance/optional callbacks, native insert/pair/value constructors/readers and archive IO execute.',
            'Bounded preallocated arrays/map storage/reset, bitvector capacity, unseen-key insert predicate, bucket rehash, shallow record copy and cleanup fixtures.',
            'Duplicate lookup and overwrite use actual callback/hash-chain instructions; no native allocator/container lifetime proof.',
            'No handler/network/session/game process/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-list-extensions-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']),truncated=len(report['truncated']))))
