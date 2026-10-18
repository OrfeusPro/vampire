"""Replay numeric display dispatch including its bounded inline switch tables."""
import csv
import hashlib
import importlib.util
import json
import math
import struct
from collections import Counter
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('format_parent',HERE/'build-stat-format-evidence.py')
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
ROOT=parent.ROOT
x=parent.x


def rule(operation_id,percentage):
    if percentage:return dict(kind='percent',scale=0.01,decimals=2,suffix='%')
    if operation_id==315:return dict(kind='scaled_number',scale=0.01,decimals=2,suffix='')
    if operation_id==453:return dict(kind='scaled_number',scale=0.001,decimals=1,suffix='')
    if 454<=operation_id<=465:return dict(kind='scaled_number',scale=0.1,decimals=1,suffix='')
    return dict(kind='integer',scale=1,decimals=0,suffix='')


class FormatRoutesEmulator(parent.StatFormatEmulator):
    def __init__(self,root=ROOT):
        super().__init__(root)
        for page in [0x14898e000,0x1489b1000]:
            self.uc.mem_map(page,4096);off=self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page,self.raw[off:off+4096]);self.uc.mem_protect(page,4096,parent.unicorn.UC_PROT_READ)
        rows={r['address']:r for f in self.fragments for r in f['instructions']}
        for address,m,o in [(0x145dda4ed,'lea','eax, [rsi - 0x13b]'),(0x145dda4f3,'cmp','eax, 0x96'),
            (0x145dda4f8,'ja','0x145dda698'),(0x145dda507,'movzx','eax, byte ptr [rdx + rax + 0x5dda798]'),
            (0x145dda50f,'mov','ecx, dword ptr [rdx + rax*4 + 0x5dda788]'),
            (0x145dda519,'jmp','rcx'),(0x145dda52a,'mulss','xmm6, dword ptr [rip + 0x2bb2c0a]'),
            (0x145dda5fa,'mulss','xmm6, dword ptr [rip + 0x2bb4806]'),
            (0x145dda68b,'mulss','xmm6, dword ptr [rip + 0x2bd7131]')]:
            r=rows[address]
            if (r['mnemonic'],r['operands'])!=(m,o):raise ValueError('Changed display switch anchor')
            self.anchors.append(r)
        off=self.image.offset(0x145dda788-self.image.pe.base)
        target_bytes=self.raw[off:off+16]
        self.targets=[self.image.pe.base+t for t in struct.unpack('<4I',target_bytes)]
        if self.targets!=[0x145dda51b,0x145dda5f3,0x145dda684,0x145dda698]:
            raise ValueError('Changed formatter targets')
        self.selectors=list(self.raw[off+16:off+16+151])
        if len(self.selectors)!=151 or any(i>=4 for i in self.selectors):raise ValueError('Invalid formatter selectors')
        if any(a not in rows for a in self.targets):raise ValueError('Switch target outside instruction boundaries')
        self.data.append(dict(address=0x145dda788,file_offset=off,bytes=self.raw[off:off+167].hex(),role='4 target RVAs and 151 byte selectors'))
        for address,content,label in [(0x14898ee08,struct.pack('<f',0.001),'scale 0.001'),
            (0x1489b17c4,struct.pack('<f',0.1),'scale 0.1'),
            (0x14899a9ac,'%s\0'.encode('utf-16le'),'no suffix string'),
            (0x1499f3870,'%.1f\0'.encode('utf-16le'),'one decimal string')]:
            off=self.image.offset(address-self.image.pe.base)
            if self.raw[off:off+len(content)]!=content:raise ValueError('Changed special display constant')
            self.data.append(dict(address=address,file_offset=off,bytes=content.hex(),role=label))

    def hook(self,uc,address,size,user):
        terminals={0x145dda427:'integer_percent',0x145dda461:'two_decimals_percent',
            0x145dda54a:'integer_scaled',0x145dda584:'two_decimals_scaled',
            0x145dda622:'integer_scaled',0x145dda644:'one_decimal_scaled',0x145dda698:'integer_unscaled'}
        if address in terminals:
            self.mode=terminals[address];uc.emu_stop();return
        if address==0x1487a2f03:super().hook(uc,address,size,user)

    def execute_route(self,operation_id,value,percentage):
        if not -(2**31)<=value<2**31:raise ValueError('Expected int32')
        uc=self.uc;self.mode=None;self.shim_calls=0
        uc.mem_write(self.base,bytes(4096));uc.mem_write(self.base+0x8c,bytes([int(percentage)]))
        for reg,v in [(x.UC_X86_REG_RAX,self.base),(x.UC_X86_REG_RBX,value & 0xffffffff),
            (x.UC_X86_REG_RSI,operation_id & 0xffffffff),(x.UC_X86_REG_RSP,self.base+0xf00),
            (x.UC_X86_REG_XMM6,0),(x.UC_X86_REG_MXCSR,0x1f80)]:uc.reg_write(reg,v)
        uc.emu_start(0x145dda3eb,0x145dda788,count=64)
        if self.mode is None:raise ValueError('No formatter terminal reached')
        bits=uc.reg_read(x.UC_X86_REG_XMM6)&0xffffffff
        return dict(mode=self.mode,scaled=value if self.mode=='integer_unscaled' else struct.unpack('<f',struct.pack('<I',bits))[0],
            shim_calls=self.shim_calls)


def main(root=ROOT):
    emulator=FormatRoutesEmulator(root)
    meta=json.loads((root/'table-study/index-pakchunk1-Windows.json').read_text('utf-8-sig'))
    t=next(t for t in meta['tables'] if t['entry']==1427);p=root/'table-study'/t['file']
    if hashlib.sha256(p.read_bytes()).hexdigest()!=t['sha256']:raise ValueError('Changed OperationType')
    with p.open(encoding='utf-8-sig',newline='') as stream:rows=list(csv.DictReader(stream))
    cases=[]
    def check(operation_id,value,percentage,origin):
        r=rule(operation_id,percentage);actual=emulator.execute_route(operation_id,value,percentage)
        if r['kind']=='integer':expected=value;mode='integer_unscaled'
        else:
            expected=parent.f32(parent.f32(value)*parent.f32(r['scale']))
            integral=abs(math.fmod(expected,1))<=parent.f32(1e-8)
            mode=('integer_percent' if integral else 'two_decimals_percent') if percentage else ('integer_scaled' if integral else 'two_decimals_scaled' if r['decimals']==2 else 'one_decimal_scaled')
        if actual['scaled']!=expected or actual['mode']!=mode:raise ValueError('Special display route mismatch')
        cases.append(dict(operation_id=operation_id,value=value,percentage=percentage,origin=origin,result=actual))
    for row in rows:
        for value in [0,1,3,50,100,150,-1,-100,16777217]:check(int(row['OperationType']),value,row['IsPercentage']=='1','CSV1427')
        r=rule(int(row['OperationType']),row['IsPercentage']=='1')
        if r['kind']=='scaled_number':check(int(row['OperationType']),round(1/r['scale']),False,'unit example')
    for operation_id in list(range(315,466))+[0,314,466,2147483647,-1,-2147483648]:
        for percentage in [False,True]:
            for value in [1,150]:check(operation_id,value,percentage,'dispatch boundary/flag precedence')
    rules={r['OperationType']:rule(int(r['OperationType']),r['IsPercentage']=='1') for r in rows}
    report=dict(source=emulator.meta['source'],sha256=emulator.meta['sha256'],csv=dict(entry=1427,sha256=t['sha256']),
        fragments=emulator.fragments,anchors=emulator.anchors,data_anchors=emulator.data,
        dispatch=dict(first_id=315,last_id=465,targets=emulator.targets,selectors=emulator.selectors),
        rules=rules,cases=cases,verified=True,stat_calculation_verified=False,
        statistics=dict(native_cases=len(cases),rules=len(rules),kinds=dict(Counter(r['kind'] for r in rules.values()))),
        limitations=['Display routing and numeric scaling only; no stat-to-stat formulas inferred.',
                    'fmodf explicit shim; full text formatting/localization is not executed.',
                    'IsPercentage precedes special ID switch. No percent suffix is used by the nonpercentage special branches.',
                    'No unit names such as kilograms, probability or game balance semantics inferred.'])
    out=root/'code-clues/stat-format-routes.json';out.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(report['statistics']))
    return report


if __name__=='__main__':main()
