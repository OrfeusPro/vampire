"""Bounded native polygon search on one explicit tile, with native internal links.

No endpoint projection, external/special links, active mesh or live filter is
implied. Native search, flag/cost checks, pool, heap and corridor emission run;
only memset and the stack-cookie check are replaced. All arrays are bounded.
"""
import importlib.util
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('path_query_parent',HERE/'recast-portal-emulator.py')
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
ENTRY=0x1452457b0
HELPERS=[ENTRY,0x14524f8f0,0x14524c750,0x145250990,0x1452553e0,
         0x14524d350,0x14523dc40,0x145250a10,0x14524fd10]
REF=1<<40


class PathQueryEmulator(parent.PortalEmulator):
    def __init__(self,root=Path('F:/PhoneExit Resources/Vampir')):
        super().__init__(root)
        spec=importlib.util.spec_from_file_location('path_query_native',HERE/'build-native-entry-code.py')
        native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
        self.query_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in HELPERS})
        self.geometry_proof=(root/'code-clues/recast-geometry-code.json').read_bytes()
        self.allowed=[(self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.query_fragments]
        self.query=self.base+0x2000;self.filter=self.base+0x3000
        self.pool=self.base+0x7000;self.poly_copy=self.base+0x8000;self.links=self.base+0xa000
        self.nodes=self.base+0x10000;self.hashes=self.base+0x18000;self.chains=self.base+0x19000
        self.heap=self.base+0x1a000;self.results=self.base+0x1c000
        self.events=[];self.counts={}

    def guard(self,uc,address,size,_):
        x=self.x
        if address==0x145246305:
            self.events.append('cookie_check_skipped');uc.reg_write(x.UC_X86_REG_RIP,address+5);return
        if address==0x1487a2e25:
            ptr=uc.reg_read(x.UC_X86_REG_RCX);value=uc.reg_read(x.UC_X86_REG_RDX);count=uc.reg_read(x.UC_X86_REG_R8)
            if ptr!=self.hashes or value!=255 or count!=1024:raise ValueError('Unexpected memset')
            uc.mem_write(ptr,b'\xff'*count);rsp=uc.reg_read(x.UC_X86_REG_RSP)
            ret=struct.unpack('<Q',uc.mem_read(rsp,8))[0]
            if ret!=0x14524594d:raise ValueError('Unexpected memset caller')
            uc.reg_write(x.UC_X86_REG_RAX,ptr);uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,ret)
            self.events.append('bounded_hash_memset');return
        if 0x14523c6c1<=address<address+size<=0x14523c77a:return
        if not any(lo<=address<hi for lo,hi in self.allowed):raise ValueError('Unexpected search code '+hex(address))
        self.counts[address]=self.counts.get(address,0)+1
        if address==0x1452553f6:raise ValueError('Output allocation forbidden')

    def prepare(self,raw,travel,entering,include,exclude,node_capacity):
        sections=parent.tile_sections(raw);pc,vc=struct.unpack_from('<HH',raw,4)
        if not 1<=pc<=256 or not 1<=node_capacity<=512:raise ValueError('Tile/pool bound')
        if len(travel)!=64 or len(entering)!=64 or any(not math.isfinite(v) or v<0 for v in travel+entering):raise ValueError('Explicit nonnegative costs required')
        if type(include) is not int or type(exclude) is not int or not 0<=include<=65535 or not 0<=exclude<=65535:raise ValueError('Flag bound')
        self.load_tiles(raw,raw);uc=self.uc
        uc.mem_write(self.query,bytes(0xa0));uc.mem_write(self.query,struct.pack('<Q',self.nav))
        uc.mem_write(self.nav+0x88,struct.pack('<I',1));uc.mem_write(self.nav+0xf0,struct.pack('<III',24,16,24))
        uc.mem_write(self.query+0x88,struct.pack('<QQ',self.pool,self.pool+0x40))
        uc.mem_write(self.pool,struct.pack('<QQQ',self.nodes,self.hashes,self.chains))
        uc.mem_write(self.pool+0x1c,struct.pack('<III',512,node_capacity,0))
        uc.mem_write(self.nodes,bytes(512*56));uc.mem_write(self.chains,bytes(1024))
        uc.mem_write(self.pool+0x40,struct.pack('<QII',self.heap,512,0))
        uc.mem_write(self.filter,bytes(0x428))
        uc.mem_write(self.filter+8,struct.pack('<64d',*travel));uc.mem_write(self.filter+0x208,struct.pack('<64d',*entering))
        uc.mem_write(self.filter+0x408,struct.pack('<d',min(travel)))
        uc.mem_write(self.filter+0x410,struct.pack('<d',1.))
        uc.mem_write(self.filter+0x418,struct.pack('<HH',include,exclude))
        uc.mem_write(self.tiles+16,struct.pack('<Q',self.poly_copy));uc.mem_write(self.tiles+32,struct.pack('<Q',self.links))
        uc.mem_write(self.poly_copy,raw[sections[16]:sections[16]+pc*32])
        # Static link capacity remains the source header count; no runtime links.
        self.adjacency=[];self.centers=[]
        capacity=struct.unpack_from('<H',raw,16)[0]
        if not 1<=capacity<=1536:raise ValueError('Static link capacity bound')
        uc.mem_write(self.tiles+4,struct.pack('<I',0))
        for i in range(capacity):uc.mem_write(self.links+16*i,struct.pack('<QIBBBB',0,i+1 if i+1<capacity else 0xffffffff,0,0,0,0))
        link_count=0
        for p in range(pc):
            off=sections[16]+32*p;count=raw[off+30]
            if raw[off+31]>=64 or not 1<=count<=6:raise ValueError('Only ordinary polygons supported')
            ids=struct.unpack_from('<6H',raw,off+4)[:count]
            if any(v>=vc for v in ids):raise ValueError('Vertex bound')
            vertices=[struct.unpack_from('<3d',raw,sections[24]+24*v) for v in ids]
            if any(not math.isfinite(value) or abs(value)>1e9 for vertex in vertices for value in vertex):raise ValueError('Finite vertex bound')
            self.centers.append([sum(v[j] for v in vertices)/count for j in range(3)])
            neighbors=[]
            for edge in reversed(range(count)):
                word=struct.unpack_from('<H',raw,off+16+2*edge)[0]
                if not word or word&0x8000:continue
                target=word-1
                link_count+=1
                if target>=pc or link_count>capacity:raise ValueError('Internal link bound')
                neighbors.append(target)
            self.adjacency.append(neighbors)
        self.pc=pc;self.raw=raw;self.sections=sections
        x=self.x
        for reg,value in [(x.UC_X86_REG_RSI,0),(x.UC_X86_REG_RDI,0),(x.UC_X86_REG_R11,REF),
                          (x.UC_X86_REG_R12,self.inputs[0]),(x.UC_X86_REG_R14,self.tiles),(x.UC_X86_REG_R15,self.nav)]:uc.reg_write(reg,value)
        uc.emu_start(0x14523c6c1,0x14523c77a,count=200000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=0x14523c77a:raise ValueError('Internal constructor instruction bound')
        self.events.append('native_internal_links')

    def search(self,raw,start,end,travel=None,entering=None,include=65535,exclude=0,node_capacity=512,cost_limit=1e300):
        if type(start) is not int or type(end) is not int:raise ValueError('Polygon indices required')
        pc=struct.unpack_from('<H',raw,4)[0]
        if not 0<=start<pc or not 0<=end<pc:raise ValueError('Endpoint bound')
        if not math.isfinite(cost_limit) or cost_limit<0:raise ValueError('Cost bound')
        self.events=[];self.counts={}
        self.prepare(raw,[1.]*64 if travel is None else travel,[0.]*64 if entering is None else entering,include,exclude,node_capacity)
        uc,x=self.uc,self.x;rsp=self.base+0x3f008
        uc.mem_write(self.output,struct.pack('<QII',self.results,0,512))
        uc.mem_write(self.output+0x40,struct.pack('<3d',*self.centers[start]))
        uc.mem_write(self.output+0x60,struct.pack('<3d',*self.centers[end]))
        uc.mem_write(rsp,struct.pack('<Q',self.base))
        for delta,value in [(0x28,self.output+0x60),(0x38,self.filter),(0x40,self.output),(0x48,self.output+0x80)]:uc.mem_write(rsp+delta,struct.pack('<Q',value))
        uc.mem_write(rsp+0x30,struct.pack('<d',cost_limit))
        for reg,value in [(x.UC_X86_REG_RSP,rsp),(x.UC_X86_REG_RCX,self.query),(x.UC_X86_REG_RDX,REF|start),
                          (x.UC_X86_REG_R8,REF|end),(x.UC_X86_REG_R9,self.output+0x40),(x.UC_X86_REG_MXCSR,0x1f80)]:uc.reg_write(reg,value)
        uc.emu_start(ENTRY,self.base,count=2000000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=self.base:raise ValueError('Search instruction bound')
        count=struct.unpack('<I',uc.mem_read(self.output+8,4))[0]
        if count>512:raise ValueError('Corridor bound')
        corridor=[];costs=[]
        for i in range(count):
            ref,cost=struct.unpack('<Qd',uc.mem_read(self.results+48*i,16))
            if ref>>24!=REF>>24 or ref&0xffffff>=pc or not math.isfinite(cost):raise ValueError('Invalid corridor row')
            corridor.append(ref&0xffffff);costs.append(cost)
        return dict(status=uc.reg_read(x.UC_X86_REG_EAX),corridor=corridor,segment_costs=costs,
                    total_cost=sum(costs),nodes=struct.unpack('<I',uc.mem_read(self.pool+0x24,4))[0],events=self.events,
                    native_helper_calls={hex(a):self.counts.get(a,0) for a in HELPERS})
