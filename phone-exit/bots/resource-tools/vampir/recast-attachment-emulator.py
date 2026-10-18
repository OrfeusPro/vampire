"""Native endpoint attachment on two local tile copies, with bounded link pools."""
import importlib.util,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('attachment_bv_base',HERE/'recast-bv-nearest-emulator.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)

class AttachmentEmulator(base.BVNearestEmulator):
    def __init__(self,root=Path('F:/PhoneExit Resources/Vampir')):
        super().__init__(root)
        spec=importlib.util.spec_from_file_location('attachment_native',HERE/'build-native-entry-code.py')
        native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
        self.attachment_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in [0x14523da30,0x14523f590,0x14524faf0]})
        self.allowed.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.attachment_fragments)
        for pointer in self.inputs:self.uc.mem_protect(pointer,0x800000,self.u.UC_PROT_READ|self.u.UC_PROT_WRITE)
        self.input_writes=[];self.allowed_input_writes=[];self.link_capacity=64

    def write_guard(self,uc,access,address,size,value,_):
        if self.base<=address<address+size<=self.base+0x40000:return
        if any(lo<=address<address+size<=hi for lo,hi in self.allowed_input_writes):
            self.input_writes.append(dict(address=address,size=size));return
        raise ValueError('Unexpected attachment input write '+hex(address))

    def prepare(self,owner,target,quantization,priorities):
        if len(quantization)!=3 or not all(math.isfinite(v) and v>0 for v in quantization):raise ValueError('Invalid attachment quantization')
        if len(priorities)!=64 or any(not isinstance(v,int) or not 0<=v<=255 for v in priorities):raise ValueError('Invalid attachment priorities')
        self.load_tiles(owner,target);self.allowed_input_writes=[];self.input_writes=[]
        self.uc.mem_write(self.nav+24,struct.pack('<3d',*quantization));self.uc.mem_write(self.nav+0x94,bytes(priorities))
        for i,raw in enumerate([owner,target]):
            sections=base.base.parent.tile_sections(raw);pointer=self.inputs[i];tile=self.tiles+168*i
            pc,vc=struct.unpack_from('<HH',raw,4)
            if raw[38]>=3:raise ValueError('Unknown attachment scale index')
            if struct.unpack_from('<H',raw,24)[0]==0:self.uc.mem_write(tile+64,bytes(8))
            for poly in range(pc):
                offset=sections[16]+32*poly;self.uc.mem_write(pointer+offset,struct.pack('<I',0xffffffff))
                self.allowed_input_writes.append((pointer+offset,pointer+offset+4))
                if raw[offset+31]>=64:
                    for vertex in struct.unpack_from('<2H',raw,offset+4):
                        if vertex>=vc:raise ValueError('Special vertex out of bounds')
                        address=pointer+88+24*vertex;self.allowed_input_writes.append((address,address+24))
            runtime=self.base+0xa000+0x1000*i
            self.uc.mem_write(tile+0x90,struct.pack('<QII',runtime,self.link_capacity,self.link_capacity))
            self.uc.mem_write(tile+0xa0,struct.pack('<I',0))
            for j in range(self.link_capacity):self.uc.mem_write(runtime+16*j,struct.pack('<QIBBH',0,j+1 if j+1<self.link_capacity else 0xffffffff,0,0,0))

    def execute(self,address,registers,cluster=False):
        x=self.x;rsp=self.base+0x3f008
        self.uc.mem_write(rsp,struct.pack('<Q',self.base));self.uc.mem_write(rsp+0x28,struct.pack('<Q',int(cluster)))
        self.uc.reg_write(x.UC_X86_REG_RSP,rsp);self.uc.reg_write(x.UC_X86_REG_MXCSR,0x1f80)
        for reg,value in registers.items():self.uc.reg_write(reg,value)
        self.uc.emu_start(address,self.base,count=2000000)
        if self.uc.reg_read(x.UC_X86_REG_RIP)!=self.base:raise ValueError('Attachment instruction bound')

    def attach(self,owner,target,quantization,priorities,special_index,side,same_tile=False):
        if side not in range(8) and side!=128:raise ValueError('Unknown attachment side')
        count=struct.unpack_from('<H',owner,26)[0]
        if not 0<=special_index<count:raise ValueError('Special point outside source')
        self.prepare(owner,target,quantization,priorities);x=self.x
        point_offset=base.base.parent.tile_sections(owner)[72]+special_index*80
        polygon=struct.unpack_from('<H',owner,point_offset+72)[0]
        self.execute(0x14523da30,{x.UC_X86_REG_RCX:self.nav,x.UC_X86_REG_RDX:self.tiles})
        start_state=self.snapshot(polygon)
        # End dispatch is explicit: caller must select the actual target tile/side.
        side_arg=-1 if side==128 else (side-4)&7
        self.execute(0x14523f590,{x.UC_X86_REG_RCX:self.nav,x.UC_X86_REG_RDX:self.tiles if same_tile else self.tiles+168,
            x.UC_X86_REG_R8:self.tiles,x.UC_X86_REG_R9:side_arg&0xffffffff})
        return dict(start_state=start_state,end_state=self.snapshot(polygon),input_writes=len(self.input_writes),
                    native_attachment_executed=True,attachment_verified=False,cluster_links_enabled=False)

    def snapshot(self,polygon):
        sections=base.base.parent.tile_sections(self.source);offset=sections[16]+32*polygon
        ids=struct.unpack_from('<2H',self.source,offset+4)
        vertices=[list(struct.unpack('<3d',self.uc.mem_read(self.inputs[0]+88+24*v,24))) for v in ids]
        all_links=[]
        for tile_index,raw in enumerate([self.source,self.target]):
            sections=base.base.parent.tile_sections(raw);pointer=self.inputs[tile_index];tile=self.tiles+168*tile_index
            static=struct.unpack_from('<H',raw,16)[0]
            for poly in range(struct.unpack_from('<H',raw,4)[0]):
                head=struct.unpack('<I',self.uc.mem_read(pointer+sections[16]+32*poly,4))[0];seen=set()
                while head!=0xffffffff:
                    if head in seen or not static<=head<static+self.link_capacity:raise ValueError('Invalid attachment list index')
                    seen.add(head);position=self.base+0xa000+0x1000*tile_index+16*(head-static)
                    reference,next_index,edge,metadata,_=struct.unpack('<QIBBH',self.uc.mem_read(position,16))
                    all_links.append(dict(source_tile_index=tile_index,source_polygon=poly,target_tile_index=(reference>>24)&0xffff,
                        target_polygon=reference&0xffffff,edge_raw=edge,metadata_raw=metadata))
                    head=next_index
        return dict(vertices_nav=vertices,links=all_links)
