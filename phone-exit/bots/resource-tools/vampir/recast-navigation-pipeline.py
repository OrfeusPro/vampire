"""Offline coordinate→projection→corridor→straight path in one bounded VM.

This composes reviewed client routines; it is not a recovered gameplay wrapper
and never issues movement commands. Partial/no-projection results have no line.
"""
import importlib.util
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
straight=load('pipeline_straight','recast-straight-path-emulator.py')
projection=load('pipeline_projection','recast-projection-emulator.py')

class NavigationPipelineEmulator(straight.StraightPathEmulator):
    configure_grid=projection.ProjectionEmulator.configure_grid
    project=projection.ProjectionEmulator.project
    route_between_points=projection.ProjectionEmulator.route_between_points

    def __init__(self,root=Path('F:/PhoneExit Resources/Vampir')):
        super().__init__(root)
        native=load('pipeline_native','build-native-entry-code.py')
        self.projection_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in projection.FUNCTIONS})
        self.allowed.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.projection_fragments)
        self.projections=[];self.route_points=None

    def guard(self,uc,address,size,extra):
        if address==0x1452457b0 and self.route_points is not None:
            for point,delta in zip(self.route_points,[0x40,0x60]):uc.mem_write(self.output+delta,struct.pack('<3d',*point))
        if address in [0x1452454ea,0x14523eee0]:
            self.events.append('projection_cookie_check_skipped');uc.reg_write(self.x.UC_X86_REG_RIP,address+5);return
        if address==0x145245277:
            rsp=uc.reg_read(self.x.UC_X86_REG_RSP);count=struct.unpack('<I',uc.mem_read(rsp+0x48,4))[0]
            if count>128:raise ValueError('Pipeline projection candidate bound')
            self.projections.append(dict(candidates=count,enumeration_status=uc.reg_read(self.x.UC_X86_REG_EAX)))
        if address in [0x1452511e8,0x1452511f7,0x14525139a]:raise ValueError('Pipeline tile-list allocation forbidden')
        super().guard(uc,address,size,extra)

    def navigate(self,start,end,extents,straight_options=0):
        projection.validate_point(start,extents);projection.validate_point(end,extents)
        if type(straight_options) is not int or straight_options not in [0,1]:raise ValueError('Pipeline supports reviewed straight options0/1')
        route=self.route_between_points(start,end,extents)
        result=dict(**route,line=None,stage='projection_missing',movement_verified=False)
        query=route['corridor_query']
        if query is None:return result
        if query['status']&0x80000000:result['stage']='query_failed';return result
        if query['status']&0x40:result['stage']='partial_corridor';return result
        result['line']=self.straight(query['corridor'],route['start_projection']['point_nav'],route['end_projection']['point_nav'],straight_options)
        result['stage']='line_built' if result['line']['status']==0x40000000 else 'line_failed'
        return result
