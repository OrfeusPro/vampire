"""Bounded native fallback nearest-surface query with explicit no-BV mode."""
import importlib.util,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('nearest_portal_base',HERE/'recast-portal-emulator.py')
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)

class NearestEmulator(parent.PortalEmulator):
    def __init__(self,root=Path('F:/PhoneExit Resources/Vampir')):
        super().__init__(root)
        spec=importlib.util.spec_from_file_location('nearest_native',HERE/'build-native-entry-code.py')
        native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
        roots=[0x145245510,0x1452513c0,0x14523e360,0x1452427e0,0x145240c20]
        self.nearest_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in roots})
        self.allowed=[(self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.nearest_fragments]
        self.query_counts=[];self.nearest_calls=0

    def guard(self,uc,address,size,_):
        if address in [0x1452456f2,0x14523e8f6]:uc.reg_write(self.x.UC_X86_REG_RIP,address+5)
        elif not any(lo<=address<hi for lo,hi in self.allowed):raise ValueError('Unexpected nearest native code '+hex(address))
        if address==0x1452455e4:
            count=uc.reg_read(self.x.UC_X86_REG_EAX)
            if count>128:raise ValueError('Nearest candidate capacity exceeded')
            self.query_counts.append(count)

    def nearest(self,point,extents):
        if len(point)!=3 or len(extents)!=3 or not all(math.isfinite(v) for v in (*point,*extents)) or min(extents)<0:raise ValueError('Invalid nearest query')
        # Exercise the explicit native fallback path. Do not infer runtime BV configuration.
        uc=self.uc;x=self.x;uc.mem_write(self.tiles+0x40,bytes(8))
        point_pointer=self.base+0x8000;extent_pointer=self.base+0x8020;output=self.base+0x8040;rsp=self.base+0x3f008
        uc.mem_write(point_pointer,struct.pack('<3d',*point));uc.mem_write(extent_pointer,struct.pack('<3d',*extents));uc.mem_write(output,bytes(24))
        uc.mem_write(rsp,struct.pack('<Q',self.base));uc.mem_write(rsp+0x28,struct.pack('<Q',output));uc.mem_write(rsp+0x30,bytes([1]))
        for reg,value in [(x.UC_X86_REG_RSP,rsp),(x.UC_X86_REG_RCX,self.nav),(x.UC_X86_REG_RDX,self.tiles),
                          (x.UC_X86_REG_R8,point_pointer),(x.UC_X86_REG_R9,extent_pointer),(x.UC_X86_REG_MXCSR,0x1f80)]:uc.reg_write(reg,value)
        before=len(self.query_counts);uc.emu_start(0x145245510,self.base,count=2000000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=self.base or len(self.query_counts)!=before+1:raise ValueError('Nearest instruction/call bound')
        ref=uc.reg_read(x.UC_X86_REG_RAX);closest=list(struct.unpack('<3d',uc.mem_read(output,24)))
        if not all(math.isfinite(v) for v in closest):raise ValueError('Nonfinite nearest result')
        polygon=(ref&0xffffff) if ref else None
        if polygon is not None and polygon>=struct.unpack_from('<H',self.source,4)[0]:raise ValueError('Nearest polygon outside source')
        self.nearest_calls+=1
        return dict(polygon=polygon,point_nav=closest,query_candidates=self.query_counts[-1],candidate_capacity=128,
                    capacity_saturated=self.query_counts[-1]==128,bv_disabled=True)
