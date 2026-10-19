"""Native CharacterSelectResult reader, with explicit bounded container fixtures."""
import ctypes
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,HERE/filename)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


base=module('select_result_base','replay-character-list-extensions.py')
math_source=module('select_result_math','replay-character-select-apply.py')
native,x=base.native,base.x
CTOR,READER,TABLE=0x1456d4a40,0x1456d8f80,0x1498d8a80
FMOD=0x1487a2efd


def basic_body(vector=(0.,0.,0.),heading=0,code=0):
    """Source-derived minimum layout: absent maps and empty arrays/strings."""
    data=bytearray(203)
    struct.pack_into('<I',data,0,code)
    struct.pack_into('<fff',data,61,*vector)
    data[73]=heading
    return bytes(data)


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        math_support=math_source.Emulator()
        self.atan2,self.apply_hooks=math_support.atan2,math_support.apply_hooks
        self.math_crt=dict(path=str(math_support.crt_path),sha256=math_support.crt_sha256)
        self.fmod=math_support.crt.fmod;self.fmod.argtypes=(ctypes.c_double,ctypes.c_double);self.fmod.restype=ctypes.c_double
        self.ranges.extend(math_support.ranges)
        manifest=json.loads((native.ROOT/'ghidra/entry-manifest.json').read_text('utf-8'))
        if manifest['source_sha256']!=self.bindings['sha256']:raise ValueError('Result manifest source mismatch')
        selected=[f for f in manifest['functions'] if f['name'].startswith(('CharacterSelect_','PktCharacterSelectResult_','Archive_ReadScalar20'))]
        self.result_ranges=[]
        for function in selected:
            for r in function['ranges']:
                if hashlib.sha256(self.raw[r['file_offset']:r['file_offset']+int(r['end_exclusive'],16)-int(r['start'],16)]).hexdigest()!=r['sha256']:
                    raise ValueError('Result source range changed')
                lo,hi=int(r['start'],16),int(r['end_exclusive'],16)
                self.ranges.append((lo,hi));self.result_ranges.append(r)
        # Float primitive referenced by ReadVector. It executes actual archive IO.
        self.float_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(0x144aa5a10)]})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.float_fragments)
        self.select_result_leaves=[]
        cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
        for address in (0x1457ecb00,0x145794d50,0x145815f60):
            off=self.image.offset(address-self.image.pe.base);instructions=[]
            for ins in cs.disasm(self.raw[off:off+128],address):
                instructions.append(ins)
                if ins.mnemonic=='ret':break
                if ins.mnemonic not in ('mov','lea','xor'):raise ValueError('Unreviewed result constructor leaf')
            if not instructions or instructions[-1].mnemonic!='ret':raise ValueError('Result constructor leaf bound')
            length=instructions[-1].address+instructions[-1].size-address
            self.select_result_leaves.append(dict(address=address,file_offset=off,bytes=self.raw[off:off+length].hex()))
            self.ranges.append((address,address+length))
        latest=json.loads((native.ROOT/'ghidra/latest-math.json').read_text('utf-8'))
        math_out=Path(latest['output']);provenance_path=math_out/'provenance.json'
        if hashlib.sha256(provenance_path.read_bytes()).hexdigest()!=latest['provenance_sha256']:raise ValueError('Math provenance changed')
        provenance=json.loads(provenance_path.read_text('utf-8'))
        if provenance['source_sha256']!=self.bindings['sha256']:raise ValueError('Math source mismatch')
        if provenance['script_sha256']!=hashlib.sha256((HERE/'ExportVampirMath.java').read_bytes()).hexdigest() or provenance['runner_sha256']!=hashlib.sha256((HERE/'run-ghidra-math.py').read_bytes()).hexdigest():
            raise ValueError('Rerun math discovery with current tools')
        for name,digest in provenance['files'].items():
            if Path(name).name!=name or hashlib.sha256((math_out/name).read_bytes()).hexdigest()!=digest:raise ValueError('Math export changed')
        self.math_ranges=provenance['ranges'];self.math_provenance_sha256=latest['provenance_sha256'];self.math_trace={}
        for r in self.math_ranges:
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset']+r['end']-r['start']]).hexdigest()!=r['sha256']:raise ValueError('Math bytes changed')
            self.ranges.append((r['start'],r['end']))
        imports=module('select_result_imports','build-object-zero-init-code.py')
        off=self.image.offset(FMOD-self.image.pe.base)
        if self.raw[off:off+2]!=b'\xff\x25':raise ValueError('Fmod import thunk changed')
        self.fmod_import=imports.import_at(self.raw,self.image,FMOD+6+struct.unpack_from('<i',self.raw,off+2)[0])
        if (self.fmod_import['dll'].lower(),self.fmod_import['name'])!=('api-ms-win-crt-math-l1-1-0.dll','fmod'):
            raise ValueError('Fmod import identity changed')
        self.select_result_hooks={0x1456b1610,0x1456d3380,0x1456b8c70}
        self.empty_resize_callbacks={0x1456b6000,0x1457846e0}
        pages={p for lo,hi in self.ranges for p in range(lo & ~4095,(hi+4095)&~4095,4096)}
        pages.update(a & ~4095 for a in (*self.select_result_hooks,*self.empty_resize_callbacks,FMOD,math_source.THUNK,TABLE))
        pages.update((a & ~4095)+4096 for a in self.select_result_hooks)
        for page in sorted(pages):self.map_source_page(page)
        self.math_events=[];self._instruction_refs={}
        self._cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);self._cs.detail=True

    def map_source_page(self,page):
        if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):return
        self.uc.mem_map(page,4096)
        try:off=self.image.offset(page-self.image.pe.base)
        except ValueError:return
        self.uc.mem_write(page,self.raw[off:off+4096])

    def hook(self,uc,address,size,user):
        # Discover data references only on actually reached source instructions;
        # function ranges come from Ghidra, not a replacement math/code parser.
        if any(lo<=address<hi for lo,hi in self.ranges):
            if address not in self._instruction_refs:
                rows=list(self._cs.disasm(bytes(uc.mem_read(address,size)),address))
                if len(rows)!=1 or rows[0].size!=size:raise ValueError('Executed result instruction decode')
                ins=rows[0]
                refs=[ins.address+ins.size+op.mem.disp for op in ins.operands
                    if op.type==native.capstone.x86_const.X86_OP_MEM and op.mem.base==native.capstone.x86_const.X86_REG_RIP]
                self._instruction_refs[address]=(refs,ins.mnemonic,ins.op_str)
            refs,mnemonic,operands=self._instruction_refs[address]
            for ref in refs:self.map_source_page(ref & ~4095)
            if any(r['start']<=address<r['end'] for r in self.math_ranges):
                self.math_trace[address]=dict(address=address,file_offset=self.image.offset(address-self.image.pe.base),
                    bytes=bytes(uc.mem_read(address,size)).hex(),mnemonic=mnemonic,operands=operands)
        if address==FMOD:
            values=[struct.unpack('<d',(uc.reg_read(r) & (2**64-1)).to_bytes(8,'little'))[0] for r in (x.UC_X86_REG_XMM0,x.UC_X86_REG_XMM1)]
            value=self.fmod(*values)
            uc.reg_write(x.UC_X86_REG_XMM0,int.from_bytes(struct.pack('<d',value),'little'))
            self.events.append(dict(action='actual_crt_fmod',args=values,value=value));self.finish(uc.reg_read(x.UC_X86_REG_RAX));return
        if address==math_source.THUNK:return math_source.Emulator.hook(self,uc,address,size,user)
        if address in self.empty_resize_callbacks:
            descriptor=uc.reg_read(x.UC_X86_REG_RDX);count=uc.reg_read(x.UC_X86_REG_R8)&65535
            if count or int.from_bytes(uc.mem_read(descriptor+12,4),'little'):
                raise ValueError('Empty resize fixture does not support allocated/nonempty input')
            uc.mem_write(descriptor+8,bytes(4));self.finish(0);return
        if address in self.select_result_hooks:
            count=uc.reg_read(x.UC_X86_REG_RDX)
            if count:raise ValueError('Result cleanup fixture only supports fresh zero-count containers')
            self.finish(uc.reg_read(x.UC_X86_REG_RAX));return
        super().hook(uc,address,size,user)

    def read_select(self,data):
        if len(data)>4096:raise ValueError('SelectResult fixture byte bound')
        self.heap=self.scratch+0x10000;self.copy_sizes=[];self.io_entries=[];self.events=[]
        self.map_storage={};self.insertions=[]
        packet,archive,buffer=self.scratch+0x1000,self.scratch+0x3000,self.scratch+0x8000
        self.uc.mem_write(packet,bytes(0x800));self.uc.mem_write(buffer,bytes(4096));self.uc.mem_write(buffer,data)
        self.call(CTOR,packet);self.call(0x144aa6260,archive,buffer,len(data),1,0)
        stack,stop=self.scratch+0x30000,self.scratch+0x3f000
        self.uc.mem_write(stack,struct.pack('<Q',stop))
        for reg,value in ((x.UC_X86_REG_RSP,stack),(x.UC_X86_REG_RCX,packet),(x.UC_X86_REG_RDX,archive)):
            self.uc.reg_write(reg,value)
        self.uc.emu_start(READER,stop,count=250000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('SelectResult reader instruction budget')
        consumed=int.from_bytes(self.uc.mem_read(archive+0x30,8),'little')-buffer
        return dict(payload_hex=data.hex(),returned=self.uc.reg_read(x.UC_X86_REG_AL),consumed=consumed,
            result_code=int.from_bytes(self.uc.mem_read(packet+0x10,4),'little'),
            vector188_hex=bytes(self.uc.mem_read(packet+0x18+0x188,24)).hex(),
            direction1b0_hex=bytes(self.uc.mem_read(packet+0x18+0x1b0,24)).hex(),
            heading_byte=int.from_bytes(self.uc.mem_read(packet+0x18+0x1a8,1),'little'))


def build():
    em=Emulator();cases=[]
    for heading in range(256):
        result=em.read_select(basic_body((1.5,-2.25,3.75),heading))
        if result['returned']!=1 or result['consumed']!=203:raise ValueError('Heading profile body mismatch')
        if result['vector188_hex']!=struct.pack('<ddd',1.5,-2.25,3.75).hex():raise ValueError('Native float expansion mismatch')
        direction=struct.unpack('<ddd',bytes.fromhex(result['direction1b0_hex']))
        if not all(math.isfinite(v) for v in direction) or not math.isclose(sum(v*v for v in direction),1.,abs_tol=1e-12):
            raise ValueError('Native direction is not a finite unit vector')
        cases.append(result)
    vector_cases=[]
    for vector in ((0.,-0.,0.),(-1.,2.,-3.),(1e-30,-1e30,16777217.)):
        for code in (0,0x26,0x3c,0xffffffff):
            body=basic_body(vector,45,code);result=em.read_select(body)
            expected=struct.pack('<ddd',*struct.unpack_from('<fff',body,61)).hex()
            if (result['returned'],result['consumed'],result['result_code'],result['vector188_hex'])!=(1,203,code,expected):
                raise ValueError('Native vector/code profile mismatch')
            vector_cases.append(result)
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),ranges=em.result_ranges,
        float_fragments=em.float_fragments,constructor_leaves=em.select_result_leaves,
        math_provenance_sha256=em.math_provenance_sha256,math_ranges=em.math_ranges,
        math_trace=sorted(em.math_trace.values(),key=lambda r:r['address']),
        crt=em.math_crt,fmod_import=em.fmod_import,minimum_body_size=203,
        vector_wire_offset=61,heading_wire_offset=73,cases=cases,vector_cases=vector_cases,
        native_execution=True,network_ready=False,
        limitations=['Actual constructor/outer and nested readers, float conversion, direction reader, Ghidra-discovered SSE2 sincos/guarded remainder execute.',
            'Imported fmod/atan2 use the actual recorded local ucrtbase DLL; no Python trigonometry replacement.',
            'Only minimum body profile: empty strings/arrays, absent optional maps; fresh zero-count cleanup and two empty resize callbacks captured.',
            'Nonempty collections and truncated bodies are not validated by this report; no complete portable ID110 decoder.',
            'Handler, acceptance/session, semantic position/world/units, lifecycle, SDK/device inputs and live session remain unverified.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-select-result-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases'])+len(report['vector_cases']))))
