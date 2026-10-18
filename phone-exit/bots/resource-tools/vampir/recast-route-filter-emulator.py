"""Execute the exact XY-distance filter-selection block before the client route-query call.

The function prologue, point projection, path search and runtime objects are
not executed. Synthetic distinct filter pointers expose the selected argument.
"""
import importlib.util
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('route_branch_parent',HERE/'recast-portal-emulator.py')
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
BEGIN=0x14569bf90
END=0x14569bffe

class RouteFilterBranchEmulator(parent.PortalEmulator):
    def __init__(self,root=Path('F:/PhoneExit Resources/Vampir')):
        super().__init__(root)
        spec=importlib.util.spec_from_file_location('route_branch_native',HERE/'build-native-entry-code.py')
        native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
        self.route_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in [0x145688dd0,BEGIN]})
        self.allowed=[(BEGIN,END)]
        self.default=self.base+0x31000;self.short=self.base+0x32000

    def guard(self,uc,address,size,extra):
        if not BEGIN<=address<address+size<=END:raise ValueError('Route branch escaped reviewed block')

    def select(self,start,end):
        for point in [start,end]:
            if not isinstance(point,(list,tuple)) or len(point)!=3 or any(isinstance(v,bool) or not isinstance(v,(int,float)) or not math.isfinite(v) or abs(v)>1e9 for v in point):
                raise ValueError('Synthetic world point outside finite 3D analysis bounds')
        uc,x=self.uc,self.x;rbp=self.base+0x20000;rsp=self.base+0x21000
        uc.mem_write(self.base+0x1000,struct.pack('<3d',*start));uc.mem_write(self.base+0x2000,struct.pack('<3d',*end))
        uc.mem_write(rbp-0x100,bytes(0x200));uc.mem_write(rsp,bytes(0x80))
        uc.mem_write(rbp+0x70,struct.pack('<Q',self.short))
        for reg,value in [(x.UC_X86_REG_RSI,self.base+0x1000),(x.UC_X86_REG_RBX,self.base+0x2000),
                          (x.UC_X86_REG_RBP,rbp),(x.UC_X86_REG_RSP,rsp),(x.UC_X86_REG_R13,self.default),
                          (x.UC_X86_REG_RDI,0),(x.UC_X86_REG_RDX,1),(x.UC_X86_REG_RAX,2),
                          (x.UC_X86_REG_MXCSR,0x1f80)]:uc.reg_write(reg,value)
        uc.emu_start(BEGIN,END,count=10000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=END:raise ValueError('Route branch instruction bound')
        pointer=struct.unpack('<Q',uc.mem_read(rsp+0x30,8))[0]
        if pointer not in (self.default,self.short):raise ValueError('Unexpected path query filter pointer')
        distance=struct.unpack('<d',struct.pack('<Q',uc.reg_read(x.UC_X86_REG_XMM1)&0xffffffffffffffff))[0]
        return dict(distance_squared_xy=distance,filter='ShortPath' if pointer==self.short else 'Default',
            path_search_executed=False,runtime_verified=False)
