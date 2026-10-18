"""Stat formatter percentage branch; native scaling/selection with explicit fmodf shim."""
import csv
import hashlib
import importlib.util
import json
import math
import struct
import sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=Path('F:/PhoneExit Resources/Vampir')
sys.path.insert(0,str(HERE.parents[2]/'.tools/vampir-analysis'))
import unicorn
from unicorn import x86_const as x


def f32(v):return struct.unpack('<f',struct.pack('<f',v))[0]


class StatFormatEmulator:
    def __init__(self,root=ROOT):
        spec=importlib.util.spec_from_file_location('stat_format_native',HERE/'build-native-entry-code.py')
        n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
        self.meta=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'))
        self.raw=Path(self.meta['source']).read_bytes()
        if hashlib.sha256(self.raw).hexdigest()!=self.meta['sha256']:raise ValueError('Changed native source')
        self.image=n.Image(self.raw)
        # .pdata includes the switch tables after RET. Decode only the explicit code span.
        lo,hi=0x145dda3a0,0x145dda788;off=self.image.offset(lo-self.image.pe.base)
        cs=n.capstone.Cs(n.capstone.CS_ARCH_X86,n.capstone.CS_MODE_64);cs.detail=True
        instructions=[]
        for ins in cs.disasm(self.raw[off:off+hi-lo],lo):
            instructions.append(dict(address=ins.address,file_offset=off+ins.address-lo,bytes=ins.bytes.hex(),
                mnemonic=ins.mnemonic,operands=ins.op_str,
                rip_references=[ins.address+ins.size+op.mem.disp for op in ins.operands
                    if op.type==n.X86_OP_MEM and op.mem.base==n.X86_REG_RIP]))
        if sum(len(bytes.fromhex(r['bytes'])) for r in instructions)!=hi-lo or instructions[-1]['mnemonic']!='ret':
            raise ValueError('Formatter code/data boundary changed')
        self.fragments=[dict(begin_rva=lo-self.image.pe.base,end_rva=hi-self.image.pe.base,
            file_offset=off,sha256=hashlib.sha256(self.raw[off:off+hi-lo]).hexdigest(),instructions=instructions,
            scope='code only, embedded switch tables excluded')]
        self.fragments+=n.decode_ranges(self.image,{self.image.roots[self.image.containing(0x145af0430)],
            self.image.roots[self.image.containing(0x145eacc70)]})
        rows={r['address']:r for f in self.fragments for r in f['instructions']}
        self.anchors=[];self.data=[]
        for a,m,o in [(0x145af065c,'lea','rax, [rip + 0x3e7f485]'),
            (0x145af0d2b,'mov','byte ptr [rdi + 0x8c], al'),
            (0x145dda3cb,'call','0x145b03700'),(0x145dda3eb,'cmp','byte ptr [rax + 0x8c], 0'),
            (0x145dda404,'cvtdq2ps','xmm6, xmm6'),
            (0x145dda407,'mulss','xmm6, dword ptr [rip + 0x2bb2d2d]'),
            (0x145dda412,'call','0x1487a2f03'),(0x145dda425,'ja','0x145dda461'),
            (0x145dda427,'cvttss2si','edx, xmm6'),(0x145eacdab,'call','0x145dda3a0')]:
            r=rows[a]
            if (r['mnemonic'],r['operands'])!=(m,o):raise ValueError('Changed format anchor '+hex(a))
            self.anchors.append(r)
        for address,content,label in [(0x14898d13c,struct.pack('<f',0.01),'float32 scale'),
            (0x14898d188,struct.pack('<f',1.0),'fmod denominator'),
            (0x14899ffc0,struct.pack('<f',1e-8),'fraction tolerance'),
            (0x14898d350,bytes.fromhex('ffffff7f')*4,'absolute-value mask'),
            (0x1499f3860,'%s%%\0'.encode('utf-16le'),'percent suffix format'),
            (0x148feded8,'%.2f\0'.encode('utf-16le'),'fraction format')]:
            off=self.image.offset(address-self.image.pe.base)
            if self.raw[off:off+len(content)]!=content:raise ValueError('Changed format literal '+label)
            self.data.append(dict(address=address,file_offset=off,bytes=content.hex(),role=label))
        spec=importlib.util.spec_from_file_location('format_import',HERE/'build-object-zero-init-code.py')
        imports=importlib.util.module_from_spec(spec);spec.loader.exec_module(imports)
        off=self.image.offset(0x1487a2f03-self.image.pe.base)
        target=0x1487a2f09+struct.unpack_from('<i',self.raw,off+2)[0]
        self.import_info=imports.import_at(self.raw,self.image,target)
        if self.import_info['name']!='fmodf':raise ValueError('Changed formatter import')
        self.uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
        self.base=0x20000000;self.uc.mem_map(self.base,4096)
        for page in {0x145dda000,0x1487a2000,0x14898d000,0x14899f000}:
            self.uc.mem_map(page,4096);off=self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page,self.raw[off:off+4096])
        self.uc.mem_write(0x1487a2f03,b'\xc3')
        for page in [0x145dda000,0x1487a2000]:
            self.uc.mem_protect(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        for page in [0x14898d000,0x14899f000]:self.uc.mem_protect(page,4096,unicorn.UC_PROT_READ)
        self.uc.hook_add(unicorn.UC_HOOK_CODE,self.hook)

    def hook(self,uc,address,size,user):
        if address in [0x145dda427,0x145dda461,0x145dda4ed]:
            self.terminal=address;uc.emu_stop()
        if address==0x1487a2f03:
            a=struct.unpack('<f',struct.pack('<I',uc.reg_read(x.UC_X86_REG_XMM0)&0xffffffff))[0]
            b=struct.unpack('<f',struct.pack('<I',uc.reg_read(x.UC_X86_REG_XMM1)&0xffffffff))[0]
            if b!=1.0:raise ValueError('Changed fmod argument')
            value=struct.unpack('<I',struct.pack('<f',math.fmod(a,b)))[0]
            uc.reg_write(x.UC_X86_REG_XMM0,value);self.shim_calls+=1

    def execute(self,value,percentage=True):
        if not -(2**31)<=value<2**31:raise ValueError('Expected int32')
        uc=self.uc;self.terminal=None;self.shim_calls=0
        uc.mem_write(self.base,bytes(4096));uc.mem_write(self.base+0x8c,bytes([int(percentage)]))
        uc.reg_write(x.UC_X86_REG_RAX,self.base);uc.reg_write(x.UC_X86_REG_RBX,value & 0xffffffff)
        uc.reg_write(x.UC_X86_REG_RSP,self.base+0xf00)
        uc.reg_write(x.UC_X86_REG_XMM6,0);uc.reg_write(x.UC_X86_REG_MXCSR,0x1f80)
        uc.emu_start(0x145dda3eb,0x145dda4ed,count=32)
        bits=uc.reg_read(x.UC_X86_REG_XMM6)&0xffffffff
        if not percentage:
            if uc.reg_read(x.UC_X86_REG_RIP)!=0x145dda4ed:raise ValueError('Nonpercentage branch changed')
            return dict(mode='other_formatter',shim_calls=self.shim_calls)
        if self.terminal not in [0x145dda427,0x145dda461]:raise ValueError('Percentage terminal not reached')
        scaled=struct.unpack('<f',struct.pack('<I',bits))[0]
        return dict(scaled=scaled,scaled_bits=hex(bits),mode='integer_percent' if self.terminal==0x145dda427 else 'two_decimals_percent',shim_calls=self.shim_calls)


def main(root=ROOT):
    emulator=StatFormatEmulator(root)
    meta=json.loads((root/'table-study/index-pakchunk1-Windows.json').read_text('utf-8-sig'))
    table=next(t for t in meta['tables'] if t['entry']==1427)
    path=root/'table-study'/table['file']
    if hashlib.sha256(path.read_bytes()).hexdigest()!=table['sha256']:raise ValueError('Changed stat CSV')
    with path.open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
    cases=[]
    for r in rows:
        for value in [0,1,3,50,100,150,-1,-100,16777217]:
            percentage=r['IsPercentage']=='1';result=emulator.execute(value,percentage)
            if percentage:
                expected=f32(f32(value)*f32(0.01))
                expected_mode='integer_percent' if abs(math.fmod(expected,1.0))<=f32(1e-8) else 'two_decimals_percent'
                if result['scaled']!=expected or result['mode']!=expected_mode:raise ValueError('Formatter mismatch')
            cases.append(dict(operation_id=r['OperationType'],percentage=percentage,value=value,result=result))
    report=dict(source=emulator.meta['source'],sha256=emulator.meta['sha256'],fragments=emulator.fragments,
        anchors=emulator.anchors,data_anchors=emulator.data,fmod_import=emulator.import_info,cases=cases,
        statistics=dict(native_cases=len(cases),percentage_records=sum(r['IsPercentage']=='1' for r in rows)),
        verified=True,display_scale=0.01,display_units='percent',stat_calculation_verified=False,
        limitations=['Only IsPercentage branch and native numeric scaling/format selector executed; fmodf is an explicit shim.',
                    'CRT text formatting, localization allocation and whole formatter are not replayed.',
                    'Nonpercentage switch has special scales; no rule for those fields is asserted here.',
                    'Display conversion is not chance, damage or inter-stat calculation.',
                    'Input is signed int32; this does not reinterpret raw 64-bit packet payloads.'])
    out=root/'code-clues/stat-format-evidence.json';out.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(report['anchors']),fragments=len(report['fragments']),**report['statistics'])))
    return report


if __name__=='__main__':main()
