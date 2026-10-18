"""Execute actual Ping serializers and buffer IO; only CRT memcpy is shimmed."""
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]/'.tools/vampir-analysis'))
import unicorn
from unicorn import x86_const as x

spec = importlib.util.spec_from_file_location('ping_native', HERE/'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)

PACKETS = {'ping': (0x1456d15c0,0x1456c1810), 'result': (0x1456e4ac0,0x1456d8600)}
READ_TABLE, WRITE_TABLE = 0x14961a520, 0x14961a5c0
FUNCTIONS = [0x144aa6260,0x144aa5850,0x144aa6530,0x144aa62f0,0x144aa5dd0,
             0x144aa68d0,0x144aa5bc0,0x144aa59c0,0x144aa5ce0,0x144aa68c0,
             0x144aa61e0,0x144aa6090,0x144aa6120,0x1445ead30,
             0x1445d9f60,0x1445d9f30]
MEMCPY = 0x1487a2e19


class PingEmulator:
    def __init__(self):
        if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4':
            raise ValueError('Use pinned Capstone 5.0.6 / Unicorn 2.1.4')
        path = native.ROOT/'code-clues/headless-packet-bindings.json'
        self.bindings_path = path
        self.bindings = json.loads(path.read_text('utf-8'))
        self.raw = Path(self.bindings['source']).read_bytes()
        if hashlib.sha256(self.raw).hexdigest() != self.bindings['sha256']:
            raise ValueError('Client source changed')
        self.image = native.Image(self.raw)
        import_spec=importlib.util.spec_from_file_location('ping_imports',HERE/'build-object-zero-init-code.py')
        imports=importlib.util.module_from_spec(import_spec)
        import_spec.loader.exec_module(imports)
        offset=self.image.offset(MEMCPY-self.image.pe.base)
        if self.raw[offset:offset+2]!=b'\xff\x25':
            raise ValueError('CRT import thunk changed')
        target=MEMCPY+6+struct.unpack_from('<i',self.raw,offset+2)[0]
        self.memcpy_import=imports.import_at(self.raw,self.image,target)
        if (self.memcpy_import['dll'].lower(),self.memcpy_import['name'])!=('vcruntime140.dll','memcpy'):
            raise ValueError('Unexpected copy import')
        self.fragments, self.leaves = [], []
        self.ranges = []
        roots = set()
        addresses = FUNCTIONS + [a for pair in PACKETS.values() for a in pair]
        decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
        for address in addresses:
            function = self.image.containing(address)
            if function is not None:
                roots.add(self.image.roots[function])
                continue
            offset = self.image.offset(address-self.image.pe.base)
            instructions = []
            for i in decoder.disasm(self.raw[offset:offset+64],address):
                instructions.append(i)
                if i.mnemonic == 'ret':
                    break
                if i.mnemonic not in ('mov','lea','xor','bswap'):
                    raise ValueError('Unreviewed leaf operation')
            if not instructions or instructions[-1].mnemonic != 'ret':
                raise ValueError('Unbounded leaf')
            size = instructions[-1].address+instructions[-1].size-address
            content = self.raw[offset:offset+size]
            self.leaves.append(dict(address=address,file_offset=offset,bytes=content.hex(),
                                    sha256=hashlib.sha256(content).hexdigest()))
            self.ranges.append((address,address+size))
        self.fragments = native.decode_ranges(self.image,roots)
        self.ranges += [(self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva'])
                        for f in self.fragments]
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
        self.scratch = 0x20000000
        self.uc.mem_map(self.scratch,0x40000)
        pages = {address & ~4095 for address in addresses+[MEMCPY]}
        for begin,end in self.ranges:
            pages.update(range(begin & ~4095,(end+4095)&~4095,4096))
        pages.add(READ_TABLE & ~4095)
        for page in pages:
            self.uc.mem_map(page,4096)
            offset = self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page,self.raw[offset:offset+4096])
            self.uc.mem_protect(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        self.uc.hook_add(unicorn.UC_HOOK_CODE,self.hook)
        self.data_anchors = []
        for table,checks in [(READ_TABLE,{0x50:0x144aa5bc0,0x58:0x144aa59c0,0x90:0x144aa5ce0}),
                             (WRITE_TABLE,{0xb8:0x144aa61e0,0xc0:0x144aa6090,0x88:0x144aa6120})]:
            for slot,target in checks.items():
                offset=self.image.offset(table+slot-self.image.pe.base)
                content=self.raw[offset:offset+8]
                if struct.unpack('<Q',content)[0] != target:
                    raise ValueError('Archive vtable changed')
                self.data_anchors.append(dict(address=table+slot,file_offset=offset,bytes=content.hex()))
        # Preserve the receive callsite proving byte-swap flag=0 and packet reader slot+0x20.
        dispatch=json.loads((native.ROOT/'code-clues/headless-network-index.json').read_text('utf-8'))
        self.dispatch_fragments=[f for f in dispatch['fragments']
                                 if f['root_begin_rva']+dispatch['image_base']==0x14679f510]
        for f in self.dispatch_fragments:
            content=self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            if hashlib.sha256(content).hexdigest()!=f['sha256']:
                raise ValueError('Dispatch evidence changed')
        dispatch_rows={i['address']:i for f in self.dispatch_fragments for i in f['instructions']}
        for address,mnemonic,operands in [
                (0x14679f52e,'movzx','ebx, word ptr [r8 + 3]'),
                (0x14679f5d7,'lea','r8d, [r9 - 5]'),
                (0x14679f5e2,'lea','rdx, [r10 + 5]'),
                (0x14679f5fb,'mov','byte ptr [rsp + 0x20], 0'),
                (0x14679f600,'call','0x144aa6260'),
                (0x14679f618,'call','qword ptr [rax + 0x20]'),
                (0x14679f6ad,'call','qword ptr [rax + 8]')]:
            row=dispatch_rows[address]
            if (row['mnemonic'],row['operands'])!=(mnemonic,operands):
                raise ValueError('Reviewed receive callsite changed')
        self.send_fragments=native.decode_ranges(self.image,
            {self.image.roots[self.image.containing(a)] for a in (0x144aa9da0,0x144aaccf0)})
        send_rows={i['address']:i for f in self.send_fragments for i in f['instructions']}
        for address in (0x144aa9e56,0x144aa9e65,0x144aace83,0x144aacee3):
            if send_rows[address]['direct_target']!=0x144aa62f0:
                raise ValueError('Output archive caller changed')

    def hook(self,uc,address,size,user):
        if address == MEMCPY:
            destination=uc.reg_read(x.UC_X86_REG_RCX)
            source=uc.reg_read(x.UC_X86_REG_RDX)
            length=uc.reg_read(x.UC_X86_REG_R8)
            if length>256 or not all(self.scratch <= a <= self.scratch+0x40000-length
                                      for a in (destination,source)):
                raise ValueError('Copy outside bounded scratch')
            if length:
                uc.mem_write(destination,bytes(uc.mem_read(source,length)))
            uc.reg_write(x.UC_X86_REG_RAX,destination)
            stack=uc.reg_read(x.UC_X86_REG_RSP)
            ret=struct.unpack('<Q',bytes(uc.mem_read(stack,8)))[0]
            uc.reg_write(x.UC_X86_REG_RSP,stack+8)
            uc.reg_write(x.UC_X86_REG_RIP,ret)
            self.copy_sizes.append(length)
            return
        if not any(begin<=address<end for begin,end in self.ranges):
            raise ValueError('Unreviewed execution target '+hex(address))
        if address in (0x144aa5bc0,0x144aa59c0,0x144aa5ce0,0x144aa61e0,0x144aa6090,0x144aa6120):
            self.io_entries.append(address)

    def call(self,address,rcx,rdx=0,r8=0,r9=0,swap=0):
        uc=self.uc;stack=self.scratch+0x30000;stop=self.scratch+0x3f000
        uc.mem_write(stack,struct.pack('<Q',stop))
        uc.mem_write(stack+0x28,bytes([swap]))
        for reg,value in [(x.UC_X86_REG_RCX,rcx),(x.UC_X86_REG_RDX,rdx),
                          (x.UC_X86_REG_R8,r8),(x.UC_X86_REG_R9,r9),(x.UC_X86_REG_RSP,stack)]:
            uc.reg_write(reg,value)
        uc.emu_start(address,stop,count=4096)
        if uc.reg_read(x.UC_X86_REG_RIP)!=stop:
            raise ValueError('Instruction budget exceeded')
        return bool(uc.reg_read(x.UC_X86_REG_AL))

    def execute(self,kind,direction,values=(0,0),payload=b'',swap=0):
        self.copy_sizes=[];self.io_entries=[]
        uc=self.uc;b=self.scratch;obj=b+0x1000;archive=b+0x2000;buffer=b+0x8000
        uc.mem_write(obj,b'\xa5'*64)
        uc.mem_write(archive,b'\0'*128)
        uc.mem_write(buffer,b'\xcc'*256)
        fmt='<QQ' if kind=='ping' else '<IQ'
        if direction=='write':
            self.call(0x144aa62f0,archive,1)
            uc.mem_write(archive+0x18,struct.pack('<QQQ',buffer,buffer,buffer+256))
            uc.mem_write(archive+0x30,struct.pack('<III',256,0,0))
            uc.mem_write(obj+0x10,struct.pack('<Q' if kind=='ping' else '<I',values[0]))
            uc.mem_write(obj+0x18,struct.pack('<Q',values[1]))
            success=self.call(PACKETS[kind][0],obj,archive)
            consumed=struct.unpack('<I',bytes(uc.mem_read(archive+0x34,4)))[0]
            output=bytes(uc.mem_read(buffer,consumed))
            if output!=struct.pack(fmt,*values):
                raise ValueError('Native byte encoding differs')
            decoded=list(values)
        else:
            uc.mem_write(buffer,payload)
            self.call(0x144aa6260,archive,buffer,len(payload),1,swap)
            success=self.call(PACKETS[kind][1],obj,archive)
            consumed=struct.unpack('<Q',bytes(uc.mem_read(archive+0x30,8)))[0]-buffer
            output=payload
            first=struct.unpack('<Q' if kind=='ping' else '<I',bytes(uc.mem_read(obj+0x10,8 if kind=='ping' else 4)))[0]
            second=struct.unpack('<Q',bytes(uc.mem_read(obj+0x18,8)))[0]
            decoded=[first,second]
        return dict(kind=kind,direction=direction,swap=swap,success=success,consumed=consumed,
                    payload_hex=output.hex(),values=decoded,copy_sizes=self.copy_sizes.copy(),
                    native_io_entries=self.io_entries.copy())


def main():
    emulator=PingEmulator();cases=[];truncated=[];swapped=[]
    values64=[0,1,0x0102030405060708,2**53+1,2**64-1]
    for kind,firsts in [('ping',values64),('result',[0,1,0x01020304,2**32-1])]:
        for first in firsts:
            for second in values64:
                values=(first,second)
                writer=emulator.execute(kind,'write',values)
                reader=emulator.execute(kind,'read',payload=bytes.fromhex(writer['payload_hex']))
                if not writer['success'] or not reader['success'] or reader['values']!=list(values):
                    raise ValueError('Native roundtrip failed')
                cases.append(dict(kind=kind,values=list(values),writer=writer,reader=reader))
        full=struct.pack('<QQ' if kind=='ping' else '<IQ',firsts[-1],values64[2])
        for length in range(len(full)+2):
            payload=(full+b'\xee')[:length]
            result=emulator.execute(kind,'read',payload=payload)
            if result['success']!=(length>=len(full)) or result['consumed']!=min(length,len(full)):
                raise ValueError('Native short/trailing buffer behavior changed')
            truncated.append(result)
        for first in [firsts[1],firsts[-1]]:
            payload=struct.pack('>QQ' if kind=='ping' else '>IQ',first,values64[2])
            result=emulator.execute(kind,'read',payload=payload,swap=1)
            if not result['success'] or result['values']!=[first,values64[2]]:
                raise ValueError('Native byte swap failed')
            swapped.append(result)
    report=dict(schema_version=1,source=emulator.bindings['source'],sha256=emulator.bindings['sha256'],
                bindings_sha256=hashlib.sha256(emulator.bindings_path.read_bytes()).hexdigest(),
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=emulator.fragments,leaves=emulator.leaves,data_anchors=emulator.data_anchors,
                dispatch_fragments=emulator.dispatch_fragments,send_fragments=emulator.send_fragments,
                memcpy_import=emulator.memcpy_import,cases=cases,buffer_cases=truncated,swap_cases=swapped,
                statistics=dict(roundtrips=len(cases),buffer_cases=len(truncated),swap_cases=len(swapped),
                                native_packet_executions=2*len(cases)+len(truncated)+len(swapped)),
                payload_layouts={'ping':'<QQ','result':'<IQ'},payload_sizes={'ping':16,'result':12},
                primitive_io_stubbed=False,external_shims=['CRT memcpy'],network_ready=False,framing_verified=False,
                limitations=['Actual native packet and primitive IO executed; only external memcpy shimmed.',
                             'Writer capacity256 is explicit preallocation; growth/allocator path not executed.',
                             'Reader constructors and swap branches executed with explicit inputs.',
                             'Unsigned raw bit patterns; field names/epoch/result semantics not inferred.',
                             'Only payload bytes established; dispatch strips5 bytes but complete frame/flags/length unknown.',
                             'No live traffic, server request, game execution or account access.'])
    path=native.ROOT/'code-clues/headless-ping-codec.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(dict(output=str(path),**report['statistics'],primitive_io_stubbed=False,network_ready=False)))


if __name__=='__main__':
    main()
