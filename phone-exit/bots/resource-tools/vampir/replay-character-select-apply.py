"""Native player apply: raw vector copy and direction-to-angle conversion."""
import ctypes
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('select_apply_base',HERE/'replay-version-packet-writer.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native,x=base.native,base.x
APPLY,ROTATION,ATAN2,THUNK=0x145d61e60,0x1415055b0,0x14143fd00,0x1487a2ef7
RESET=0x3000b000


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.apply_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in (APPLY,ROTATION)})
        self.ranges.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.apply_fragments)
        off=self.image.offset(ATAN2-self.image.pe.base);data=self.raw[off:off+27]
        if data.hex()!='0f28d00f57c0660f2ec87506660f2ed074080f28c2e9dd313607c3':
            raise ValueError('Reviewed guarded atan2 wrapper changed')
        self.atan2_leaf=dict(address=ATAN2,file_offset=off,bytes=data.hex())
        self.ranges.append((ATAN2,ATAN2+27))
        off=self.image.offset(THUNK-self.image.pe.base)
        if self.raw[off:off+2]!=b'\xff\x25':raise ValueError('Atan2 thunk changed')
        slot=THUNK+6+struct.unpack_from('<i',self.raw,off+2)[0]
        spec=importlib.util.spec_from_file_location('select_apply_imports',HERE/'build-object-zero-init-code.py')
        imports=importlib.util.module_from_spec(spec);spec.loader.exec_module(imports)
        self.math_import=imports.import_at(self.raw,self.image,slot)
        if (self.math_import['dll'].lower(),self.math_import['name'])!=('api-ms-win-crt-math-l1-1-0.dll','atan2'):
            raise ValueError('Math import identity changed')
        self.crt_path=Path(os.environ['SystemRoot'])/'System32/ucrtbase.dll'
        self.crt_sha256=hashlib.sha256(self.crt_path.read_bytes()).hexdigest()
        self.crt=ctypes.CDLL(str(self.crt_path));self.atan2=self.crt.atan2
        self.atan2.argtypes=(ctypes.c_double,ctypes.c_double);self.atan2.restype=ctypes.c_double
        self.apply_hooks={RESET,THUNK,0x145d7bce0,0x145d7bf90,0x145d7db30,0x14143c260,0x1458819c0,0x141482990}
        refs=[a for f in self.apply_fragments for r in f['instructions'] for a in r['rip_references']]
        pages={p for lo,hi in self.ranges for p in range(lo & ~4095,(hi+4095)&~4095,4096)}
        pages.update(a & ~4095 for a in (*refs,*self.apply_hooks))
        pages.update((a & ~4095)+4096 for a in self.apply_hooks if a>0x140000000)
        for page in sorted(pages):
            if any(lo<=page<=hi for lo,hi,_ in self.uc.mem_regions()):continue
            self.uc.mem_map(page,4096)
            try:off=self.image.offset(page-self.image.pe.base)
            except ValueError:continue
            self.uc.mem_write(page,self.raw[off:off+4096])
        off=self.image.offset(0x1489b1990-self.image.pe.base)
        self.degrees_constant=dict(address=0x1489b1990,file_offset=off,bytes=self.raw[off:off+8].hex())

    def finish(self,result):
        self.uc.reg_write(x.UC_X86_REG_RAX,result)
        sp=self.uc.reg_read(x.UC_X86_REG_RSP)
        self.uc.reg_write(x.UC_X86_REG_RIP,int.from_bytes(self.uc.mem_read(sp,8),'little'))
        self.uc.reg_write(x.UC_X86_REG_RSP,sp+8)

    def hook(self,uc,address,size,user):
        if address not in self.apply_hooks:return super().hook(uc,address,size,user)
        a,b=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX)]
        result=0
        if address==THUNK:
            y,z=[struct.unpack('<d',(uc.reg_read(reg) & (2**64-1)).to_bytes(8,'little'))[0] for reg in (x.UC_X86_REG_XMM0,x.UC_X86_REG_XMM1)]
            if not all(math.isfinite(v) for v in (y,z)):raise ValueError('Math fixture finite input bound')
            value=self.atan2(y,z)
            uc.reg_write(x.UC_X86_REG_XMM0,int.from_bytes(struct.pack('<d',value),'little'))
            self.events.append(dict(action='actual_crt_atan2',args=[y,z],value=value))
        elif address==RESET:
            if a!=self.scratch+0x2000 or b:raise ValueError('Apply reset receiver/argument changed')
            self.events.append(dict(action='player_virtual60_capture'))
        elif address in (0x145d7bce0,0x145d7bf90,0x145d7db30):
            self.events.append(dict(action='nested_apply_capture',address=address,offset=b-(self.scratch+0x1000)))
        elif address==0x14143c260:
            if bytes(uc.mem_read(b,16))!=bytes(16):raise ValueError('Only empty text fixture supported')
            uc.mem_write(a,bytes(16));result=a
        elif address==0x1458819c0:
            uc.mem_write(a,bytes(16));result=a
        self.finish(result)

    def execute_apply(self,raw_vector,direction,raw_flag):
        self.events=[];self.heap=self.scratch+0x10000;self.copy_sizes=[];self.io_entries=[]
        source,dest,table=self.scratch+0x1000,self.scratch+0x2000,self.scratch+0x3000
        self.uc.mem_write(source,bytes(0x278));self.uc.mem_write(dest,bytes(0x400))
        self.uc.mem_write(dest,struct.pack('<Q',table));self.uc.mem_write(table+0x60,struct.pack('<Q',RESET))
        self.uc.mem_write(source+8,struct.pack('<Q',0x123456789abcdef))
        self.uc.mem_write(source+0x30,struct.pack('<I',207))
        self.uc.mem_write(source+0x188,struct.pack('<ddd',*raw_vector))
        self.uc.mem_write(source+0x1b0,struct.pack('<ddd',*direction))
        self.uc.mem_write(source+0x260,bytes([raw_flag]))
        self.call(APPLY,dest,source)
        return dict(raw_vector_input=list(raw_vector),direction_input=list(direction),raw_flag=raw_flag,
            copied_vector_hex=bytes(self.uc.mem_read(dest+0x20,24)).hex(),
            rotation=list(struct.unpack('<ddd',bytes(self.uc.mem_read(dest+0x38,24)))),
            raw8=int.from_bytes(self.uc.mem_read(dest+8,8),'little'),
            raw10=int.from_bytes(self.uc.mem_read(dest+0x10,4),'little'),
            derived249=int.from_bytes(self.uc.mem_read(dest+0x249,1),'little'),events=self.events.copy())


def build():
    em=Emulator();cases=[]
    raw_vector=(1234.5,-987.25,42.125)
    for vector in ((0.,0.,0.),(1.,0.,0.),(0.,1.,0.),(-1.,0.,0.),(0.,0.,1.),(0.,0.,-1.),
            (3.,4.,5.),(-3.,4.,-5.),(3e100,4e100,5e100),(3e-100,4e-100,5e-100),(-0.,-0.,0.)):
        for flag in (0,2):
            c=em.execute_apply(raw_vector,vector,flag)
            atan=lambda a,b:0. if a==0 and b==0 else math.atan2(a,b)
            expected=(math.degrees(atan(vector[2],math.sqrt(vector[0]**2+vector[1]**2))),math.degrees(atan(vector[1],vector[0])),0.)
            if c['copied_vector_hex']!=struct.pack('<ddd',*raw_vector).hex() or any(not math.isclose(a,b,abs_tol=1e-12,rel_tol=1e-12) for a,b in zip(c['rotation'],expected)):
                raise ValueError('Native raw vector copy/rotation mismatch')
            cases.append(c)
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),fragments=em.apply_fragments,
        atan2_leaf=em.atan2_leaf,math_import=em.math_import,crt=dict(path=str(em.crt_path),sha256=em.crt_sha256),
        degrees_constant=em.degrees_constant,cases=cases,native_execution=True,network_ready=False,
        limitations=['Actual player apply and vector-to-angles routines/guarded atan2 wrapper execute; external imported atan2 uses actual recorded local ucrtbase DLL.',
            'Source player record and destination vtable/object are synthetic, nested appearance/map helpers/empty text/class lookup/reset captured, listener list empty.',
            'Source+188 raw24 is copied to destination+20; source+1b0 direction is converted into pitch/yaw/zero roll at destination+38.',
            'Wire encoding/nested player reader, coordinate/world units and semantic position consumer remain separate evidence; no live position/session/game/Android.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-select-apply-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']))))
