"""Execute LoginResult constructor, nested time readers and UTF-8 archive input."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('login_result_base', HERE/'replay-version-packet-writer.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
CTOR, READER, TABLE = 0x1456d4da0, 0x1456d9600, 0x1498d6218
STRINGS = (0x18, 0x28, 0x38, 0x70, 0x90, 0xb8, 0xc8)
U32 = (0x10, 0x130, 0x134)
U16 = (0x48, 0x60)
U64 = (0x58, 0x68, 0x80, 0xb0, 0xf0, 0x100, 0x110, 0x120)
BOOL = (0x88, 0xa0, 0xe0, 0x128, 0x138)
ORDER = (('i',0x10),('s',0x18),('s',0x28),('s',0x38),('h',0x48),('q',0x58),
    ('h',0x60),('q',0x68),('s',0x70),('q',0x80),('b',0x88),('s',0x90),('b',0xa0),
    ('q',0xb0),('s',0xb8),('s',0xc8),('b',0xe0),('q',0xf0),('q',0x100),('q',0x110),
    ('q',0x120),('b',0x128),('i',0x130),('i',0x134),('b',0x138))


def payload(fields):
    parts = []
    for kind, offset in ORDER:
        value = fields[{'i':'u32','h':'u16','q':'u64','b':'bool','s':'strings'}[kind]][hex(offset)]
        if kind == 's':
            data = value.encode('utf-8')
            parts.extend((struct.pack('<H', len(data)), data))
        else:
            parts.append(struct.pack({'i':'<I','h':'<H','q':'<Q','b':'<B'}[kind], value))
    return b''.join(parts)


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        addresses = (CTOR, READER, 0x145794c20, 0x1457986b0, 0x1457f0a90,
            0x144aa66f0, 0x144aa5ab0, 0x144aa5970, 0x144aa5c10, 0x144aa5b90,
            0x141446940, 0x141440ba0, 0x141436230, 0x141435ea0)
        self.result_fragments = native.decode_ranges(self.image, {
            self.image.roots[self.image.containing(a)] for a in addresses})
        self.ranges.extend((self.image.pe.base+f['begin_rva'], self.image.pe.base+f['end_rva']) for f in self.result_fragments)
        self.result_leaves = []
        for address, length in ((0x1457eca60, 0x16), (0x144aa68b0, 0x10), (0x144aa5960, 0xf)):
            offset = self.image.offset(address-self.image.pe.base)
            data = self.raw[offset:offset+length]
            self.result_leaves.append(dict(address=address, file_offset=offset, bytes=data.hex(),
                sha256=hashlib.sha256(data).hexdigest()))
            self.ranges.append((address,address+length))
        self.result_hooks = {0x141421dd0, 0x1421e1730}
        refs = [a for f in self.result_fragments for r in f['instructions'] for a in r['rip_references']]
        pages = {p for begin,end in self.ranges for p in range(begin & ~4095,(end+4095) & ~4095,4096)}
        pages.update(a & ~4095 for a in (*refs,*self.result_hooks,TABLE,0x1498cf2c8,0x1498d61d0))
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page,4096)
            try: offset = self.image.offset(page-self.image.pe.base)
            except ValueError: continue
            self.uc.mem_write(page,self.raw[offset:offset+4096])

    def hook(self, uc, address, size, user):
        if address in self.result_hooks:
            a,b,c,d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
            if address == 0x141421dd0:
                data = bytearray()
                if b:
                    for index in range(512):
                        pair = bytes(uc.mem_read(b+2*index,2))
                        if pair == b'\0\0': break
                        data.extend(pair)
                    else: raise ValueError('FString assignment bound')
                pointer = self.alloc(len(data)+2) if data else 0
                if data: uc.mem_write(pointer,bytes(data)+b'\0\0')
                n = len(data)//2+1 if data else 0
                uc.mem_write(a,struct.pack('<QII',pointer,n,n))
            else:
                length,capacity = struct.unpack('<QQ',bytes(uc.mem_read(a+16,16)))
                if b != 1 or length > 1024:
                    raise ValueError('StdString growth fixture bound')
                old = int.from_bytes(uc.mem_read(a,8),'little') if capacity>15 else a
                data = bytes(uc.mem_read(old,length)) if length else b''
                pointer = self.alloc(max(32,(length+2)*2))
                uc.mem_write(pointer,data+bytes((d & 255,0)))
                uc.mem_write(a,struct.pack('<QQQQ',pointer,0,length+1,max(32,(length+2)*2)-1))
            uc.reg_write(x.UC_X86_REG_RAX,a)
            sp = uc.reg_read(x.UC_X86_REG_RSP)
            ret = int.from_bytes(uc.mem_read(sp,8),'little')
            uc.reg_write(x.UC_X86_REG_RSP,sp+8)
            uc.reg_write(x.UC_X86_REG_RIP,ret)
            return
        if address == 0x1414311c0:
            # Reader scratch allocation uses UTF-16 units, writer uses bytes.
            a,b,c,d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
            if b or d != 2:
                raise ValueError('Reader UTF-16 scratch fixture changed')
            uc.mem_write(a,struct.pack('<Q',self.alloc(c*2)))
            sp = uc.reg_read(x.UC_X86_REG_RSP)
            uc.reg_write(x.UC_X86_REG_RIP,int.from_bytes(uc.mem_read(sp,8),'little'))
            uc.reg_write(x.UC_X86_REG_RSP,sp+8)
            return
        super().hook(uc,address,size,user)

    def read(self, data):
        if len(data)>4096: raise ValueError('Reader payload fixture bound')
        self.heap = self.scratch+0x10000
        self.copy_sizes,self.io_entries = [],[]
        packet,archive,buffer = self.scratch+0x1000,self.scratch+0x2000,self.scratch+0x8000
        self.uc.mem_write(packet,b'\xa5'*0x140)
        self.uc.mem_write(buffer,bytes(4096))
        self.uc.mem_write(buffer,data)
        self.call(CTOR,packet)
        self.call(0x144aa6260,archive,buffer,len(data),1,0)
        stack,stop = self.scratch+0x30000,self.scratch+0x3f000
        self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,packet),(x.UC_X86_REG_RDX,archive)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(READER,stop,count=250000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop: raise ValueError('LoginResult reader budget')
        fields = dict(strings={})
        for offset in STRINGS:
            pointer,n,capacity = struct.unpack('<QII',bytes(self.uc.mem_read(packet+offset,16)))
            if not 0<=n<=capacity<=1024: raise ValueError('Decoded FString bound')
            fields['strings'][hex(offset)] = bytes(self.uc.mem_read(pointer,(n-1)*2)).decode('utf-16le') if n else ''
        for offsets,key,fmt,size in ((U32,'u32','<I',4),(U16,'u16','<H',2),(U64,'u64','<Q',8),(BOOL,'bool','<B',1)):
            fields[key] = {hex(o):struct.unpack(fmt,bytes(self.uc.mem_read(packet+o,size)))[0] for o in offsets}
        consumed = int.from_bytes(self.uc.mem_read(archive+0x30,8),'little')-buffer
        return dict(payload_hex=data.hex(),returned=self.uc.reg_read(x.UC_X86_REG_AL),consumed=consumed,fields=fields)


def build():
    upstream = native.ROOT/'code-clues/login-send-path-replay.json'
    prior = json.loads(upstream.read_text('utf-8'))
    emulator = Emulator()
    if emulator.bindings['sha256']!=prior['sha256']: raise ValueError('LoginResult source mismatch')
    fields = dict(strings={hex(o):'' for o in STRINGS},u32={hex(o):0 for o in U32},
        u16={hex(o):0 for o in U16},u64={hex(o):0 for o in U64},bool={hex(o):0 for o in BOOL})
    cases = []
    for text in ('','ASCII-15-values','a'*16,'a'*128,'Ж界','🙂','é'*80):
        current = dict(fields,strings={hex(o):text for o in STRINGS},
            u32={hex(o):v for o,v in zip(U32,(0,207,0xffffffff))},
            u16={'0x48':0xffff,'0x60':0x8000},
            u64={hex(o):0xfedcba9876543210+i for i,o in enumerate(U64)},
            bool={hex(o):v for o,v in zip(BOOL,(0,1,2,255,1))})
        case = emulator.read(payload(current))
        wanted = dict(current,bool={k:int(bool(v)) for k,v in current['bool'].items()})
        if case['returned']!=1 or case['fields']!=wanted or case['consumed']!=len(bytes.fromhex(case['payload_hex'])):
            raise ValueError('LoginResult native field layout mismatch')
        cases.append(case)
    minimal = payload(fields)
    if len(minimal)!=99: raise ValueError('LoginResult minimum changed')
    for code in (1,14,22,37,54,9400,9818,9819,90021,0xffffffff):
        current = dict(fields,u32=dict(fields['u32'], **{'0x10':code}))
        case = emulator.read(payload(current))
        if case['returned']!=1 or case['fields']!=current:
            raise ValueError('LoginResult raw result code decode changed')
        cases.append(case)
    for flag in (0,1,2,255):
        current = dict(fields,bool={hex(o):flag for o in BOOL})
        case = emulator.read(payload(current))
        if case['returned']!=1 or case['fields']!=dict(current,bool={hex(o):int(bool(flag)) for o in BOOL}):
            raise ValueError('LoginResult bool normalization changed')
        cases.append(case)
    truncated = [emulator.read(minimal[:n]) for n in range(99)]
    text_truncated = []
    for text in ('x','🙂'):
        data = payload(dict(fields,strings={hex(o):text for o in STRINGS}))
        text_truncated.extend(emulator.read(data[:n]) for n in range(len(data)))
    trailing = emulator.read(minimal+b'extra')
    anchors = []
    for table,size in ((TABLE,0x40),(0x1498cf2c8,0x30),(0x1498d61d0,0x30),(base.ping.READ_TABLE,0x98)):
        offset = emulator.image.offset(table-emulator.image.pe.base)
        anchors.append(dict(address=table,file_offset=offset,bytes=emulator.raw[offset:offset+size].hex()))
    binding = next(p for p in emulator.bindings['packets'] if p['name']=='PktLoginResult')
    if (binding['constructor'],binding['reader'],binding['vtable'],binding['packet_id'])!=(CTOR,READER,TABLE,4):
        raise ValueError('LoginResult packet binding changed')
    for anchor,target in zip(anchors[:3],(READER,0x1457f0a90,0x1457986b0)):
        if struct.unpack_from('<Q',bytes.fromhex(anchor['bytes']),0x20)[0]!=target:
            raise ValueError('LoginResult nested read slot changed')
    return dict(schema_version=1,source=emulator.bindings['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(upstream.read_bytes()).hexdigest(),
        fragments=emulator.result_fragments,leaves=emulator.result_leaves,anchors=anchors,packet_binding=binding,
        cases=cases,truncated=truncated,text_truncated=text_truncated,trailing=trailing,native_execution=True,network_ready=False,
        limitations=['Actual LoginResult constructor/reader/nested time and period readers/stdstring input/UTF-8 conversion execute.',
            'FString assignment, stdstring growth, allocator/free/memcpy/cookie bounded fixtures.',
            'Valid terminated strings only; malformed UTF-8/NUL/large allocations unverified.',
            'Independent response body run, not listener/Dispatch/handler/session; scalar meanings not inferred.',
            'No game launch/profile/process memory/credentials/network/server response/Android.'])


if __name__=='__main__':
    report = build()
    path = native.ROOT/'code-clues/login-result-reader-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']),truncated=len(report['truncated']))))
