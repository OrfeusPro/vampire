"""Native stat/detail serialization structure. Primitive IO is synthetic, wire bytes unknown."""
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=Path('F:/PhoneExit Resources/Vampir')
sys.path.insert(0,str(HERE.parents[2]/'.tools/vampir-analysis'))
import unicorn
from unicorn import x86_const as x

READERS={'stat':0x1457f0540,'category':0x1457f0590}
WRITERS={'stat':0x1457f4360,'category':0x145784940}


class StatPacketEmulator:
    def __init__(self,root=ROOT):
        spec=importlib.util.spec_from_file_location('stat_packet_native',HERE/'build-native-entry-code.py')
        n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
        self.meta=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'))
        self.raw=Path(self.meta['source']).read_bytes()
        if hashlib.sha256(self.raw).hexdigest()!=self.meta['sha256']:raise ValueError('Changed client')
        self.image=n.Image(self.raw)
        funcs=list(READERS.values())+list(WRITERS.values())+[0x1456ce110,0x1456ce140,
            0x1456ce1a0,0x1456ce200,0x1456ce230,0x1457f0660,0x1457f4430,
            0x145798060,0x14579af70,0x1456c1f20,0x1456cb990,0x146767e10]
        self.fragments=n.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in funcs})
        rows={r['address']:r for f in self.fragments for r in f['instructions']}
        self.anchors=[];self.data=[]
        for va,m,o in [(0x1457f0553,'lea','rdx, [rcx + 8]'),(0x1457f0564,'lea','rdx, [rdi + 0x10]'),
            (0x1457f05bb,'mov','r9d, 0x1d'),(0x1457f05c7,'cmovb','r9d, eax'),
            (0x1457f05cb,'mov','byte ptr [rdi + 8], r9b'),
            (0x1457f4370,'mov','edx, dword ptr [rcx + 8]'),
            (0x1457f4389,'mov','rdx, qword ptr [rdi + 0x10]'),
            (0x145784950,'movzx','edx, byte ptr [rcx + 8]'),
            (0x14578496a,'mov','rdx, qword ptr [rdi + 0x10]'),
            (0x14579af7a,'mov','rdx, qword ptr [rcx + 8]')]:
            r=rows[va]
            if (r['mnemonic'],r['operands'])!=(m,o):raise ValueError('Changed stat packet anchor '+hex(va))
            self.anchors.append(r)
        for va,text,encoding in [(0x1456ce119,'PktStat','ascii'),(0x1456ce149,'PktStatCategoryData','ascii'),
            (0x1456ce1a9,'PktStatDetailData','ascii'),(0x1456ce209,'PktStatDetailInfoReadResult','ascii'),
            (0x1456ce239,'PktStatExtraCategoryData','ascii'),
            (0x1456cba12,'StatDetailDataList','ascii'),
            (0x146767e14,'PktStatDetailInfoReadResultHandler::OnHandler()','utf-16le')]:
            r=rows[va];target=r['rip_references'][0];off=self.image.offset(target-self.image.pe.base)
            content=(text+'\0').encode(encoding)
            if self.raw[off:off+len(content)]!=content:raise ValueError('Changed packet literal')
            self.anchors.append(r);self.data.append(dict(address=target,file_offset=off,bytes=content.hex(),text=text))
        for base,slots in [(0x1498d1b30,{0x10:WRITERS['stat'],0x20:READERS['stat'],0x28:0x1456ce110}),
            (0x1498d2638,{0x10:WRITERS['category'],0x20:READERS['category'],0x28:0x1456ce140}),
            (0x1498d26d0,{0x10:0x1457f4430,0x20:0x1457f0660,0x28:0x1456ce1a0}),
            (0x1498d2680,{0x10:0x14579af70,0x20:0x145798060,0x28:0x1456ce230})]:
            for offset,target in slots.items():
                off=self.image.offset(base+offset-self.image.pe.base);content=struct.pack('<Q',target)
                if self.raw[off:off+8]!=content:raise ValueError('Changed packet vtable')
                self.data.append(dict(address=base+offset,file_offset=off,bytes=content.hex(),role='packet vtable slot'))
        self.uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
        self.base=0x20000000;self.uc.mem_map(self.base,0x10000)
        for page in {a & ~4095 for a in list(READERS.values())+list(WRITERS.values())}:
            self.uc.mem_map(page,4096);off=self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page,self.raw[off:off+4096])
            self.uc.mem_protect(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        self.stubs={self.base+0x8000+i*16:slot for i,slot in enumerate([0x58,0x50,0x78,0xc0,0xb8,0xe0])}
        for address in self.stubs:self.uc.mem_write(address,b'\xc3')
        self.uc.hook_add(unicorn.UC_HOOK_CODE,self.hook)

    def hook(self,uc,address,size,user):
        if address not in self.stubs:return
        slot=self.stubs[address];self.calls.append(slot)
        if self.fail_at==len(self.calls):
            uc.reg_write(x.UC_X86_REG_RAX,0);return
        argument=uc.reg_read(x.UC_X86_REG_RDX)
        if self.direction=='read':
            if slot==0x58:content=struct.pack('<I',self.key & 0xffffffff)
            elif slot==0x78:content=bytes([self.key])
            elif slot==0x50:content=struct.pack('<Q',self.payload)
            else:raise ValueError('Unexpected primitive read slot')
            uc.mem_write(argument,content)
        else:self.output.append(argument)
        uc.reg_write(x.UC_X86_REG_RAX,1)

    def execute(self,kind,key,payload,direction='read',fail_at=0):
        self.key=key;self.payload=payload;self.direction=direction;self.fail_at=fail_at;self.calls=[];self.output=[]
        uc=self.uc;b=self.base;obj=b+0x1000;archive=b+0x2000;vtable=b+0x3000
        uc.mem_write(obj,b'\xa5'*0x30)
        if direction=='write':
            uc.mem_write(obj+8,struct.pack('<I',key & 0xffffffff) if kind=='stat' else bytes([key]))
            uc.mem_write(obj+0x10,struct.pack('<Q',payload))
        uc.mem_write(archive,struct.pack('<Q',vtable))
        for a,slot in self.stubs.items():uc.mem_write(vtable+slot,struct.pack('<Q',a))
        uc.mem_write(b+0xf000,struct.pack('<Q',b+0xe000))
        uc.reg_write(x.UC_X86_REG_RCX,obj);uc.reg_write(x.UC_X86_REG_RDX,archive)
        uc.reg_write(x.UC_X86_REG_RSP,b+0xf000)
        uc.emu_start((READERS if direction=='read' else WRITERS)[kind],b+0xe000,count=128)
        if uc.reg_read(x.UC_X86_REG_RIP)!=b+0xe000:raise ValueError('Packet boundary mismatch')
        result=bool(uc.reg_read(x.UC_X86_REG_AL));memory=bytes(uc.mem_read(obj,0x30))
        return dict(success=result,key=struct.unpack_from('<I',memory,8)[0] if kind=='stat' else memory[8],
            payload_hex=memory[0x10:0x18].hex(),calls=self.calls.copy(),output=[hex(v) for v in self.output])


def main(root=ROOT):
    emulator=StatPacketEmulator(root);cases=[]
    for kind,keys in [('stat',range(208)),('category',range(256))]:
        for key in keys:
            for payload in [0,2**53+1,2**64-1]:
                read=emulator.execute(kind,key,payload)
                expected=key if kind=='stat' else min(key,29)
                if not read['success'] or read['key']!=expected or read['payload_hex']!=struct.pack('<Q',payload).hex():
                    raise ValueError('Native stat field read mismatch')
                write=emulator.execute(kind,expected,payload,'write')
                if not write['success'] or write['output']!=[hex(expected),hex(payload)]:
                    raise ValueError('Native stat field write mismatch')
                cases.append(dict(kind=kind,key=key,payload_hex=struct.pack('<Q',payload).hex(),read=read,write=write))
    failures=[]
    for kind in READERS:
        for direction in ['read','write']:
            for fail in [1,2]:
                result=emulator.execute(kind,7,123,direction,fail)
                if result['success'] or len(result['calls'])!=fail:raise ValueError('Primitive failure not propagated')
                failures.append(dict(kind=kind,direction=direction,fail_at=fail,result=result))
    report=dict(source=emulator.meta['source'],sha256=emulator.meta['sha256'],fragments=emulator.fragments,
        anchors=emulator.anchors,data_anchors=emulator.data,cases=cases,failure_cases=failures,
        statistics=dict(roundtrips=len(cases),native_reader_calls=len(cases)+4,native_writer_calls=len(cases)+4,failures=8),
        schemas=[dict(name='PktStat',key_offset=8,key_width=4,value_offset=16,value_width=8),
                 dict(name='PktStatCategoryData',category_offset=8,category_width=1,category_read_upper_bound=29,value_offset=16,value_width=8),
                 dict(name='PktStatExtraCategoryData',value_offset=8,value_width=8),
                 dict(name='PktStatDetailData',key_offset=8,category_array_offset=16,extra_array_offset=32)],
        verified=True,formula_verified=False,live_values_available=False,category_names_verified=False,
        limitations=['Readers/writers executed with synthetic primitive IO stubs; actual wire encoding/signedness not reconstructed.',
                    'Numeric values are raw 64-bit payloads, not floating-point guesses or live character stats.',
                    'No network traffic, login, game process or actual server data used.',
                    'PktStatDetailData vector plumbing statically inspected, not replayed with nested allocations.',
                    'PktStatDetailInfoReadResultHandler name found, but function146767e10 is logging-only; no population of a character model proved.',
                    'Category cap29 is structural behavior, not verified names/count of obtainable sources.',
                    'Packet schemas alone do not prove all stat calculations are server-side.'])
    path=root/'code-clues/stat-packet-evidence.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(report['anchors']),fragments=len(report['fragments']),**report['statistics'])))
    return report


if __name__=='__main__':main()
