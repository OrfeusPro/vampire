"""Native two-tile construction, external/special attachment and polygon query.

Explicit offline inputs only. Runtime custom-link callbacks and cluster links
are disabled; capacities and all executable functions are bounded.
"""
import importlib.util
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('linked_query_parent',HERE/'recast-path-query-emulator.py')
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
EXTRA=[0x14523f0e0,0x14523da30,0x14523f590,0x14524faf0,
       0x145243b00,0x145245510,0x1452513c0,0x14523e360,0x1452427e0]


class LinkedPathEmulator(parent.PathQueryEmulator):
    def __init__(self,root=Path('F:/PhoneExit Resources/Vampir')):
        super().__init__(root)
        spec=importlib.util.spec_from_file_location('linked_query_native',HERE/'build-native-entry-code.py')
        native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
        self.linked_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in EXTRA})
        for f in self.linked_fragments+self.fragments:self.allowed.append((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']))
        self.extra=0x5000000;self.uc.mem_map(self.extra,0x40000)
        self.temporary=self.extra+0x23000;self.temporary_active=False

    def write_guard(self,uc,access,address,size,value,extra):
        if self.extra<=address<address+size<=self.extra+0x40000:return
        super().write_guard(uc,access,address,size,value,extra)

    def guard(self,uc,address,size,extra):
        x=self.x
        if address in [0x14524441c,0x1452456f2,0x14523e8f6,0x145243d39]:
            self.events.append('geometry_cookie_check_skipped');uc.reg_write(x.UC_X86_REG_RIP,address+5);return
        if address in [0x1452455e4,0x145243be7]:
            if uc.reg_read(x.UC_X86_REG_EAX)>128:raise ValueError('Nearest candidate capacity')
        if address==0x14523f120:
            if self.temporary_active or uc.reg_read(x.UC_X86_REG_RCX)!=384 or uc.reg_read(x.UC_X86_REG_RDX)!=0:raise ValueError('External temporary allocation bound')
            self.temporary_active=True;uc.mem_write(self.temporary,bytes(384))
            uc.reg_write(x.UC_X86_REG_RAX,self.temporary);uc.reg_write(x.UC_X86_REG_RIP,address+6)
            self.events.append('bounded_external_temporary_alloc');return
        if address==0x14523f56e:
            if not self.temporary_active or uc.reg_read(x.UC_X86_REG_RCX)!=self.temporary:raise ValueError('External temporary free mismatch')
            self.temporary_active=False;uc.reg_write(x.UC_X86_REG_RIP,address+6);self.events.append('bounded_external_temporary_free');return
        if address in [0x14523f252,0x14523f286,0x145255350,0x145255256]:raise ValueError('Dynamic link/portal allocation forbidden')
        super().guard(uc,address,size,extra)

    def execute(self,address,registers):
        uc,x=self.uc,self.x;rsp=self.base+0x3f008
        uc.mem_write(rsp,struct.pack('<Q',self.base));uc.mem_write(rsp+0x28,bytes(8))
        uc.reg_write(x.UC_X86_REG_RSP,rsp);uc.reg_write(x.UC_X86_REG_MXCSR,0x1f80)
        for reg,value in registers.items():uc.reg_write(reg,value)
        uc.emu_start(address,self.base,count=2000000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=self.base:raise ValueError('Linked execution instruction bound')

    def prepare_pair(self,raws,height,quantization,priorities,travel,entering,include,exclude,node_capacity):
        if len(raws)!=2:raise ValueError('Exactly two explicit tiles required')
        if not math.isfinite(height) or height<0:raise ValueError('Height bound')
        if len(quantization)!=3 or any(not math.isfinite(v) or v<=0 for v in quantization):raise ValueError('Quantization bound')
        if len(priorities)!=64 or any(type(v) is not int or not 0<=v<=255 for v in priorities):raise ValueError('Priority bound')
        if type(node_capacity) is not int or not 1<=node_capacity<=512:raise ValueError('Node bound')
        if len(travel)!=64 or len(entering)!=64 or any(not math.isfinite(v) or v<0 for v in travel+entering):raise ValueError('Cost bound')
        if any(type(v) is not int or not 0<=v<=65535 for v in [include,exclude]):raise ValueError('Flag bound')
        self.events=[];self.counts={};self.uc.mem_write(self.base,bytes(0x3e000));self.uc.mem_write(self.extra,bytes(0x40000))
        self.load_tiles(*raws);uc,x=self.uc,self.x
        uc.mem_write(self.nav+16,struct.pack('<d',height));uc.mem_write(self.nav+24,struct.pack('<3d',*quantization))
        uc.mem_write(self.nav+0x88,struct.pack('<I',2));uc.mem_write(self.nav+0x94,bytes(priorities))
        uc.mem_write(self.nav+0xe8,struct.pack('<Q',self.tiles));uc.mem_write(self.nav+0xf0,struct.pack('<III',24,16,24))
        self.raws=raws;self.sections=[];self.centers_pair=[];self.poly_counts=[]
        self.poly_pointers=[self.poly_copy,self.extra+0x1000];self.link_pointers=[self.links,self.extra+0x4000]
        self.vertex_pointers=[self.extra+0x14000,self.extra+0x10000]
        self.runtime_pointers=[self.extra+0x20000,self.extra+0x21000]
        for ti,raw in enumerate(raws):
            sections=parent.parent.tile_sections(raw);pc,vc=struct.unpack_from('<HH',raw,4);capacity=struct.unpack_from('<H',raw,16)[0]
            if not 1<=pc<=256 or not 1<=vc<=512 or not 1<=capacity<=1536 or raw[38]>=3:raise ValueError('Pair tile capacity')
            self.sections.append(sections);self.poly_counts.append(pc);tile=self.tiles+168*ti
            uc.mem_write(self.poly_pointers[ti],raw[sections[16]:sections[16]+pc*32])
            uc.mem_write(self.vertex_pointers[ti],raw[88:88+vc*24])
            uc.mem_write(tile+4,struct.pack('<I',0));uc.mem_write(tile+16,struct.pack('<QQQ',self.poly_pointers[ti],self.vertex_pointers[ti],self.link_pointers[ti]))
            if not struct.unpack_from('<H',raw,24)[0]:uc.mem_write(tile+64,bytes(8))
            for j in range(capacity):uc.mem_write(self.link_pointers[ti]+16*j,struct.pack('<QIBBBB',0,j+1 if j+1<capacity else 0xffffffff,0,0,0,0))
            runtime=self.runtime_pointers[ti];uc.mem_write(tile+0x90,struct.pack('<QIII',runtime,64,64,0))
            for j in range(64):uc.mem_write(runtime+16*j,struct.pack('<QIBBBB',0,j+1 if j<63 else 0xffffffff,0,0,0,0))
            centers=[];internal_count=0
            for p in range(pc):
                off=sections[16]+32*p;count=raw[off+30]
                if not 1<=count<=6 or raw[off+31]>>6 not in [0,1,2]:raise ValueError('Polygon type/count')
                ids=struct.unpack_from('<6H',raw,off+4)[:count]
                if any(v>=vc for v in ids):raise ValueError('Vertex bound')
                vertices=[struct.unpack_from('<3d',raw,88+24*v) for v in ids]
                if any(not math.isfinite(v) or abs(v)>1e9 for vertex in vertices for v in vertex):raise ValueError('Vertex finite bound')
                centers.append([sum(v[j] for v in vertices)/count for j in range(3)])
                for word in struct.unpack_from('<6H',raw,off+16)[:count]:
                    if word and not word&0x8000:
                        if word-1>=pc:raise ValueError('Neighbor bound')
                        internal_count+=1
            if internal_count>capacity:raise ValueError('Internal link capacity')
            self.centers_pair.append(centers)
            for reg,value in [(x.UC_X86_REG_RSI,0),(x.UC_X86_REG_RDI,0),(x.UC_X86_REG_R11,parent.REF|(ti<<24)),
                (x.UC_X86_REG_R12,self.inputs[ti]),(x.UC_X86_REG_R14,tile),(x.UC_X86_REG_R15,self.nav)]:uc.reg_write(reg,value)
            uc.emu_start(0x14523c6c1,0x14523c77a,count=200000)
            if uc.reg_read(x.UC_X86_REG_RIP)!=0x14523c77a:raise ValueError('Internal constructor bound')
        uc.mem_write(self.query,struct.pack('<Q',self.nav));uc.mem_write(self.query+0x88,struct.pack('<QQ',self.pool,self.pool+0x40))
        uc.mem_write(self.pool,struct.pack('<QQQ',self.nodes,self.hashes,self.chains));uc.mem_write(self.pool+0x1c,struct.pack('<III',512,node_capacity,0))
        uc.mem_write(self.pool+0x40,struct.pack('<QII',self.heap,512,0))
        uc.mem_write(self.filter+8,struct.pack('<64d',*travel));uc.mem_write(self.filter+0x208,struct.pack('<64d',*entering))
        uc.mem_write(self.filter+0x408,struct.pack('<ddHH',min(travel),1.,include,exclude))
        self.events.append('native_pair_internal_links')

    def connect_external(self,side):
        if side not in [0,2,4,6]:raise ValueError('External side bound')
        x=self.x
        for ti,direction in [(0,side),(1,(side-4)&7)]:
            self.execute(0x14523f0e0,{x.UC_X86_REG_RCX:self.nav,x.UC_X86_REG_RDX:self.tiles+168*ti,
                x.UC_X86_REG_R8:self.tiles+168*(1-ti),x.UC_X86_REG_R9:direction})
        if self.temporary_active:raise ValueError('Unreleased portal temporary')

    def connect_special(self,side,same_tile=False):
        if side not in range(8) and side!=128:raise ValueError('Special side bound')
        x=self.x
        self.execute(0x14523da30,{x.UC_X86_REG_RCX:self.nav,x.UC_X86_REG_RDX:self.tiles})
        self.execute(0x14523f590,{x.UC_X86_REG_RCX:self.nav,x.UC_X86_REG_RDX:self.tiles if same_tile else self.tiles+168,
            x.UC_X86_REG_R8:self.tiles,x.UC_X86_REG_R9:(-1 if side==128 else (side-4)&7)&0xffffffff})

    def snapshot(self):
        rows=[];vertices=[]
        for ti,raw in enumerate(self.raws):
            static=struct.unpack_from('<H',raw,16)[0]
            vertices.append([list(struct.unpack('<3d',self.uc.mem_read(self.vertex_pointers[ti]+24*v,24))) for v in range(struct.unpack_from('<H',raw,6)[0])])
            for p in range(self.poly_counts[ti]):
                head=struct.unpack('<I',self.uc.mem_read(self.poly_pointers[ti]+32*p,4))[0];seen=set()
                while head!=0xffffffff:
                    if head in seen or head>=static+64:raise ValueError('Link index/cycle bound')
                    seen.add(head);ptr=self.link_pointers[ti]+16*head if head<static else self.runtime_pointers[ti]+16*(head-static)
                    ref,nxt,edge,metadata,low,high=struct.unpack('<QIBBBB',self.uc.mem_read(ptr,16))
                    target=(ref>>24)&65535;poly=ref&0xffffff
                    if ref>>40!=1 or target>=2 or poly>=self.poly_counts[target]:raise ValueError('Link reference bound')
                    rows.append(dict(source=[ti,p],target=[target,poly],edge=edge,metadata=metadata,low=low,high=high))
                    head=nxt
        return dict(links=rows,vertices=vertices)

    def search_prepared(self,start,end,cost_limit=1e300):
        for point in [start,end]:
            if len(point)!=2 or any(type(v) is not int for v in point) or not 0<=point[0]<2 or not 0<=point[1]<self.poly_counts[point[0]]:raise ValueError('Pair endpoint bound')
        if not math.isfinite(cost_limit) or cost_limit<0:raise ValueError('Cost limit bound')
        uc,x=self.uc,self.x;rsp=self.base+0x3f008
        uc.mem_write(self.output,struct.pack('<QII',self.results,0,512))
        for point,delta in [(start,0x40),(end,0x60)]:uc.mem_write(self.output+delta,struct.pack('<3d',*self.centers_pair[point[0]][point[1]]))
        uc.mem_write(rsp,struct.pack('<Q',self.base))
        for delta,value in [(0x28,self.output+0x60),(0x38,self.filter),(0x40,self.output),(0x48,self.output+0x80)]:uc.mem_write(rsp+delta,struct.pack('<Q',value))
        uc.mem_write(rsp+0x30,struct.pack('<d',cost_limit))
        for reg,value in [(x.UC_X86_REG_RSP,rsp),(x.UC_X86_REG_RCX,self.query),
            (x.UC_X86_REG_RDX,parent.REF|(start[0]<<24)|start[1]),(x.UC_X86_REG_R8,parent.REF|(end[0]<<24)|end[1]),
            (x.UC_X86_REG_R9,self.output+0x40),(x.UC_X86_REG_MXCSR,0x1f80)]:uc.reg_write(reg,value)
        uc.emu_start(parent.ENTRY,self.base,count=2000000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=self.base:raise ValueError('Linked query instruction bound')
        count=struct.unpack('<I',uc.mem_read(self.output+8,4))[0]
        if count>512:raise ValueError('Linked corridor count')
        corridor=[];costs=[]
        for i in range(count):
            ref,cost=struct.unpack('<Qd',uc.mem_read(self.results+48*i,16));ti=(ref>>24)&65535;p=ref&0xffffff
            if ref>>40!=1 or ti>=2 or p>=self.poly_counts[ti] or not math.isfinite(cost):raise ValueError('Corridor reference bound')
            corridor.append([ti,p]);costs.append(cost)
        return dict(status=uc.reg_read(x.UC_X86_REG_EAX),corridor=corridor,segment_costs=costs,total_cost=sum(costs),
            nodes=struct.unpack('<I',uc.mem_read(self.pool+0x24,4))[0],events=list(self.events),
            native_helper_calls={hex(a):self.counts.get(a,0) for a in parent.HELPERS+EXTRA})
