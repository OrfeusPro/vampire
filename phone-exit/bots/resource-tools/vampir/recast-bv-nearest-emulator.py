"""Native BV and area-priority nearest queries with explicit candidate settings."""
import importlib.util,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('bv_nearest_base',HERE/'recast-nearest-emulator.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)

class BVNearestEmulator(base.NearestEmulator):
    def __init__(self,root=Path('F:/PhoneExit Resources/Vampir')):
        super().__init__(root)
        spec=importlib.util.spec_from_file_location('bv_nearest_native',HERE/'build-native-entry-code.py')
        native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
        extra=[0x145243b00,0x14524dd50,0x1452b9210]
        self.bv_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in extra})
        self.allowed.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.bv_fragments if f['root_begin_rva']==0x5243b00)

    def guard(self,uc,address,size,_):
        if address==0x145243d39:uc.reg_write(self.x.UC_X86_REG_RIP,address+5)
        elif address==0x145243be7:
            count=uc.reg_read(self.x.UC_X86_REG_EAX)
            if count>128:raise ValueError('Preferred nearest capacity exceeded')
            self.query_counts.append(count)
        else:super().guard(uc,address,size,_)

    def query(self,point,extents,quantization,priorities=None):
        if len(point)!=3 or len(extents)!=3 or not all(math.isfinite(v) for v in (*point,*extents)) or min(extents)<0:raise ValueError('Invalid BV query')
        if len(quantization)!=3 or not all(math.isfinite(v) and v>0 for v in quantization):raise ValueError('Invalid BV quantization')
        if priorities is not None and (len(priorities)!=64 or any(not isinstance(v,int) or not 0<=v<=255 for v in priorities)):raise ValueError('Invalid area priorities')
        uc=self.uc;x=self.x;sections=base.parent.tile_sections(self.source)
        count=struct.unpack_from('<H',self.source,24)[0];scale_index=self.source[38]
        if scale_index>=len(quantization):raise ValueError('Unknown BV scale index')
        uc.mem_write(self.tiles+0x40,struct.pack('<Q',self.inputs[0]+sections[64] if count else 0))
        uc.mem_write(self.nav+24,struct.pack('<3d',*quantization))
        if priorities is not None:uc.mem_write(self.nav+0x94,bytes(priorities))
        point_pointer=self.base+0x8000;extent_pointer=self.base+0x8020;output=self.base+0x8040;rsp=self.base+0x3f008
        uc.mem_write(point_pointer,struct.pack('<3d',*point));uc.mem_write(extent_pointer,struct.pack('<3d',*extents));uc.mem_write(output,bytes(24))
        uc.mem_write(rsp,struct.pack('<Q',self.base));uc.mem_write(rsp+0x28,struct.pack('<Q',output));uc.mem_write(rsp+0x30,bytes([1]))
        for reg,value in [(x.UC_X86_REG_RSP,rsp),(x.UC_X86_REG_RCX,self.nav),(x.UC_X86_REG_RDX,self.tiles),
                          (x.UC_X86_REG_R8,point_pointer),(x.UC_X86_REG_R9,extent_pointer),(x.UC_X86_REG_MXCSR,0x1f80)]:uc.reg_write(reg,value)
        before=len(self.query_counts);uc.emu_start(0x145243b00 if priorities is not None else 0x145245510,self.base,count=2000000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=self.base or len(self.query_counts)!=before+1:raise ValueError('BV nearest instruction bound')
        ref=uc.reg_read(x.UC_X86_REG_RAX);closest=list(struct.unpack('<3d',uc.mem_read(output,24)));polygon=(ref&0xffffff) if ref else None
        if not all(math.isfinite(v) for v in closest) or polygon is not None and polygon>=struct.unpack_from('<H',self.source,4)[0]:raise ValueError('Invalid BV query result')
        self.nearest_calls+=1
        return dict(polygon=polygon,point_nav=closest,query_candidates=self.query_counts[-1],candidate_capacity=128,
                    capacity_saturated=self.query_counts[-1]==128,bv_used=bool(count),scale_index=scale_index,
                    preferred_query=priorities is not None)
