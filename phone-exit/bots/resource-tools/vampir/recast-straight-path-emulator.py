"""Native straight-path/funnel with bounded arrays and explicit initialized TLS.

The OS/static-initialization environment is synthetic; epsilon is copied from
the exact client initializer literal. No CRT initialization or game process runs.
"""
import importlib.util
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('straight_linked_parent',HERE/'recast-linked-path-emulator.py')
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
FUNCTIONS=[0x145248b20,0x14523df90,0x14524d870,0x14522e870,0x14523ce30]

class StraightPathEmulator(parent.LinkedPathEmulator):
    def __init__(self,root=Path('F:/PhoneExit Resources/Vampir')):
        super().__init__(root)
        spec=importlib.util.spec_from_file_location('straight_native',HERE/'build-native-entry-code.py')
        native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
        self.straight_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in FUNCTIONS})
        self.allowed.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.straight_fragments)
        self.static_values={};rows={r['address']:r for f in self.straight_fragments for r in f['instructions']}
        literal=rows[0x145249296]['rip_references'][0];target=rows[0x1452492a5]['rip_references'][0]
        if literal!=0x149714d48 or target!=0x14b566188:raise ValueError('Changed funnel initializer')
        offset=self.image.offset(literal-self.image.pe.base);raw=self.data[offset:offset+8]
        if raw.hex()!='000000000000303e':raise ValueError('Changed native equality threshold')
        self.initialized_epsilon=dict(address=literal,file_offset=offset,raw_hex=raw.hex(),value=struct.unpack('<d',raw)[0],target=target)
        for address,size,value in [(target,8,raw),(0x14b566190,4,bytes(4)),(0x14b6313f0,4,bytes(4))]:
            rva=address-self.image.pe.base
            if not any(s['rva']+s['raw_size']<=rva<rva+size<=s['rva']+s['size'] for s in self.image.pe.sections):raise ValueError('Static input not PE zero-fill')
            self.static_values[address]=(size,value)
        self.static_mapped=set();self.teb=0x6000000;self.tls=0x6100000
        self.uc.mem_map(self.teb,0x2000,self.u.UC_PROT_READ);self.uc.mem_map(self.tls,0x102000,self.u.UC_PROT_READ)
        self.uc.mem_write(self.teb+0x58,struct.pack('<Q',self.teb+0x1000));self.uc.mem_write(self.teb+0x1000,struct.pack('<Q',self.tls))
        self.uc.reg_write(self.x.UC_X86_REG_GS_BASE,self.teb)

    def map_page(self,uc,access,address,size,value,extra):
        entries=getattr(self,'static_values',{})
        if any((a&~4095)==(address&~4095) for a in entries):
            if access!=self.u.UC_MEM_READ_UNMAPPED or address not in entries or size!=entries[address][0]:raise ValueError('Unexpected static environment read')
            page=address&~4095;uc.mem_map(page,4096,self.u.UC_PROT_READ)
            for a,(length,raw) in entries.items():
                if a&~4095==page:uc.mem_write(a,raw)
            self.static_mapped.add(page);return True
        return super().map_page(uc,access,address,size,value,extra)

    def guard(self,uc,address,size,extra):
        if address==0x14523e349:
            self.events.append('endpoint_clamp_cookie_check_skipped');uc.reg_write(self.x.UC_X86_REG_RIP,address+5);return
        if address in [0x14879656c,0x148796500]:raise ValueError('CRT initialization forbidden')
        super().guard(uc,address,size,extra)

    def straight(self,corridor,start,end,options=0):
        if not isinstance(corridor,list) or not 1<=len(corridor)<=512:raise ValueError('Corridor capacity')
        for point in corridor:
            if len(point)!=2 or any(type(v) is not int for v in point) or not 0<=point[0]<2 or not 0<=point[1]<self.poly_counts[point[0]]:raise ValueError('Corridor reference bound')
        for vector in [start,end]:
            if len(vector)!=3 or any(type(v) not in [int,float] or not math.isfinite(v) or abs(v)>1e9 for v in vector):raise ValueError('Endpoint finite bound')
        if type(options) is not int or options not in [0,1,2]:raise ValueError('Unsupported straight path option')
        uc,x=self.uc,self.x;array=self.extra+0x28000;points=self.extra+0x28100;refs=self.extra+0x28200;output=self.extra+0x2a000;rsp=self.base+0x3f008
        uc.mem_write(array,struct.pack('<QII',output,0,512));uc.mem_write(output,bytes(512*48))
        uc.mem_write(points,struct.pack('<3d',*start));uc.mem_write(points+0x20,struct.pack('<3d',*end))
        uc.mem_write(refs,b''.join(struct.pack('<Q',parent.parent.REF|(p[0]<<24)|p[1]) for p in corridor))
        uc.mem_write(rsp,struct.pack('<Q',self.base));uc.mem_write(rsp+0x28,struct.pack('<Q',len(corridor)))
        uc.mem_write(rsp+0x30,struct.pack('<Q',array));uc.mem_write(rsp+0x38,struct.pack('<Q',options))
        for reg,value in [(x.UC_X86_REG_RSP,rsp),(x.UC_X86_REG_RCX,self.query),(x.UC_X86_REG_RDX,points),
            (x.UC_X86_REG_R8,points+0x20),(x.UC_X86_REG_R9,refs),(x.UC_X86_REG_MXCSR,0x1f80)]:uc.reg_write(reg,value)
        uc.emu_start(0x145248b20,self.base,count=2000000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=self.base:raise ValueError('Straight path instruction bound')
        count=struct.unpack('<I',uc.mem_read(array+8,4))[0]
        if count>512:raise ValueError('Straight output bound')
        result=[]
        for i in range(count):
            row=bytes(uc.mem_read(output+48*i,48));ref=struct.unpack_from('<Q',row)[0];point=list(struct.unpack_from('<3d',row,16));flags=struct.unpack_from('<I',row,40)[0]
            if any(not math.isfinite(v) for v in point):raise ValueError('Invalid straight output point')
            polygon=None if not ref else [(ref>>24)&65535,ref&0xffffff]
            if ref and (ref>>40!=1 or polygon[0]>=2 or polygon[1]>=self.poly_counts[polygon[0]]):raise ValueError('Straight output reference')
            result.append(dict(polygon=polygon,point_nav=point,flags=flags))
        return dict(status=uc.reg_read(x.UC_X86_REG_EAX),points=result,options=options,
            helper_calls={hex(a):self.counts.get(a,0) for a in FUNCTIONS})
