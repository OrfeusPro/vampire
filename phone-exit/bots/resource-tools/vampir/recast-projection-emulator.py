"""Execute full endpoint projection with an explicit bounded two-tile hash grid."""
import importlib.util
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('projection_linked_parent',HERE/'recast-linked-path-emulator.py')
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
FUNCTIONS=[0x1452451b0,0x145250f50,0x1452519d0,0x14523e910]

def validate_point(point,extents):
    for vector in [point,extents]:
        if not isinstance(vector,(list,tuple)) or len(vector)!=3 or any(type(v) not in [int,float] or not math.isfinite(v) or abs(v)>1e9 for v in vector):raise ValueError('Finite 3D inputs required')
    if any(v<0 or v>1000 for v in extents):raise ValueError('Explicit projection extents limited to0..1000')

class ProjectionEmulator(parent.LinkedPathEmulator):
    def __init__(self,root=Path('F:/PhoneExit Resources/Vampir')):
        super().__init__(root)
        spec=importlib.util.spec_from_file_location('projection_native',HERE/'build-native-entry-code.py')
        native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
        self.projection_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in FUNCTIONS})
        self.allowed.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.projection_fragments)
        self.projections=[]
        self.route_points=None

    def guard(self,uc,address,size,extra):
        if address==0x1452457b0 and self.route_points is not None:
            for point,delta in zip(self.route_points,[0x40,0x60]):uc.mem_write(self.output+delta,struct.pack('<3d',*point))
        if address in [0x1452454ea,0x14523eee0]:
            self.events.append('projection_cookie_check_skipped');uc.reg_write(self.x.UC_X86_REG_RIP,address+5);return
        if address==0x145245277:
            rsp=uc.reg_read(self.x.UC_X86_REG_RSP)
            count=struct.unpack('<I',uc.mem_read(rsp+0x48,4))[0]
            if count>128:raise ValueError('Projection candidate bound')
            self.projections.append(dict(candidates=count,enumeration_status=uc.reg_read(self.x.UC_X86_REG_EAX)))
        if address in [0x1452511e8,0x1452511f7,0x14525139a]:raise ValueError('Projection tile-list allocation forbidden')
        super().guard(uc,address,size,extra)

    def configure_grid(self,origin,widths):
        if len(origin)!=3 or any(not math.isfinite(v) or abs(v)>1e9 for v in origin):raise ValueError('Grid origin bound')
        if len(widths)!=2 or any(not math.isfinite(v) or v<1000 for v in widths):raise ValueError('Grid widths must be explicit and>=1000')
        # Mask0: both synthetic loaded tiles form one hash chain. Headers retain
        # their source grid coordinates, so the native coordinate test still runs.
        uc=self.uc
        uc.mem_write(self.nav+0x60,struct.pack('<3d',*origin));uc.mem_write(self.nav+0x78,struct.pack('<2d',*widths))
        uc.mem_write(self.nav+0x90,bytes(4));uc.mem_write(self.nav+0xd8,struct.pack('<Q',self.extra+0x24000))
        uc.mem_write(self.extra+0x24000,struct.pack('<Q',self.tiles))
        uc.mem_write(self.tiles+0x60,struct.pack('<Q',self.tiles+168));uc.mem_write(self.tiles+168+0x60,bytes(8))
        self.grid=dict(origin=origin,widths=widths,mask=0,loaded_tiles=2)

    def project(self,point,extents,alternate=None):
        validate_point(point,extents)
        if alternate is not None:validate_point(alternate,extents)
        uc,x=self.uc,self.x;scratch=self.extra+0x26000;rsp=self.base+0x3f008
        uc.mem_write(scratch,struct.pack('<3d',*point));uc.mem_write(scratch+0x20,struct.pack('<3d',*extents))
        uc.mem_write(scratch+0x40,bytes(8));uc.mem_write(scratch+0x60,struct.pack('<3d',9e200,9e200,9e200))
        if alternate is not None:uc.mem_write(scratch+0x80,struct.pack('<3d',*alternate))
        uc.mem_write(rsp,struct.pack('<Q',self.base))
        for delta,value in [(0x28,scratch+0x40),(0x30,scratch+0x60),(0x38,0 if alternate is None else scratch+0x80)]:uc.mem_write(rsp+delta,struct.pack('<Q',value))
        for reg,value in [(x.UC_X86_REG_RSP,rsp),(x.UC_X86_REG_RCX,self.query),(x.UC_X86_REG_RDX,scratch),
            (x.UC_X86_REG_R8,scratch+0x20),(x.UC_X86_REG_R9,self.filter),(x.UC_X86_REG_MXCSR,0x1f80)]:uc.reg_write(reg,value)
        before=len(self.projections);uc.emu_start(0x1452451b0,self.base,count=2000000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=self.base or len(self.projections)!=before+1:raise ValueError('Projection execution bound')
        ref=struct.unpack('<Q',uc.mem_read(scratch+0x40,8))[0];closest=list(struct.unpack('<3d',uc.mem_read(scratch+0x60,24)))
        polygon=None
        if ref:
            ti=(ref>>24)&65535;p=ref&0xffffff
            if ref>>40!=1 or ti>=2 or p>=self.poly_counts[ti] or not all(math.isfinite(v) for v in closest):raise ValueError('Projection result bound')
            polygon=[ti,p]
        else:
            if closest!=[9e200]*3:raise ValueError('No-hit projection unexpectedly wrote closest point')
        return dict(status=uc.reg_read(x.UC_X86_REG_EAX),polygon=polygon,point_nav=closest if ref else None,
            **self.projections[-1],candidate_capacity=128,capacity_saturated=self.projections[-1]['candidates']==128)

    def route_between_points(self,start,end,extents):
        start_projection=self.project(start,extents);end_projection=self.project(end,extents)
        result=None
        if start_projection['polygon'] is not None and end_projection['polygon'] is not None:
            self.route_points=[start_projection['point_nav'],end_projection['point_nav']]
            try:result=self.search_prepared(start_projection['polygon'],end_projection['polygon'])
            finally:self.route_points=None
        return dict(start_projection=start_projection,end_projection=end_projection,corridor_query=result)
