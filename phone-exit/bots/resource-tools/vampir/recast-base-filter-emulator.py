"""Native base-filter initialization with bounded allocation and explicit CDOs.

The complete initializer, constructor, shared-reference move, area entering
getter and concrete cost setters execute. Allocation/CDO loading and the
global mask use synthetic inputs; no live client object is inspected.
"""
import hashlib
import importlib.util
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('base_filter_parent',HERE/'recast-filter-apply-emulator.py')
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
FLOAT_MAX=struct.unpack('<f',bytes.fromhex('ffff7f7f'))[0]

def float32(value):
    if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or abs(value)>FLOAT_MAX:
        raise ValueError('Invalid explicit float32')
    return struct.unpack('<f',struct.pack('<f',value))[0]

def validate_inputs(areas,owner_5bc,owner_5d0,owner_644,blocked_flags):
    if not isinstance(areas,list) or len(areas)>64:raise ValueError('Invalid supported area count')
    float32(owner_5bc);float32(owner_644)
    if type(owner_5d0) is not int or not 0<=owner_5d0<=0xffffffff:raise ValueError('Invalid owner flags')
    if type(blocked_flags) is not int or not 0<=blocked_flags<=65535:raise ValueError('Invalid blocked flags')
    for area in areas:
        if not isinstance(area,dict) or set(area)!={'area_id','class_state','travel','entering'}:raise ValueError('Incomplete supported area input')
        if type(area['area_id']) is not int or not 0<=area['area_id']<64:raise ValueError('Invalid area ID')
        if area['class_state'] not in ('present','create','null_cdo','null_class'):raise ValueError('Unknown CDO state')
        float32(area['travel']);float32(area['entering'])


class BaseFilterEmulator(parent.FilterApplyEmulator):
    def __init__(self,root=Path('F:/PhoneExit Resources/Vampir')):
        super().__init__(root)
        spec=importlib.util.spec_from_file_location('base_filter_native',HERE/'build-native-entry-code.py')
        native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
        self.base_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in [0x1452b7120,0x14146d9e0]})
        self.allowed.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.base_fragments)
        getter=0x14527f810;offset=self.image.offset(getter-self.image.pe.base);raw=self.data[offset:offset+6]
        if raw.hex()!='f30f104134c3':raise ValueError('Changed entering-cost getter')
        self.entering_getter=dict(address=getter,file_offset=offset,raw_hex=raw.hex())
        self.allowed.append((getter,getter+6))
        table=0x149721c28;offset=self.image.offset(table+0x2e8-self.image.pe.base);raw=self.data[offset:offset+8]
        if struct.unpack('<Q',raw)[0]!=getter:raise ValueError('Changed area virtual getter slot')
        self.area_vtable=dict(table=table,slot=0x2e8,file_offset=offset,raw_hex=raw.hex(),target=getter)
        self.refcounter=self.base+0x1a000;self.cdo_base=self.base+0x15000
        rows={r['address']:r for f in self.base_fragments for r in f['instructions']}
        self.mask_address=rows[0x1452b7244]['rip_references'][0]
        self.mask_mapped=False;self.events=[];self.allocations=[];self.area_inputs=[]

    def map_page(self,uc,access,address,size,value,extra):
        mask=getattr(self,'mask_address',0)
        if mask and (address&~4095)==(mask&~4095):
            if access!=self.u.UC_MEM_READ_UNMAPPED or address!=mask or size!=2:raise ValueError('Unexpected mask-page access')
            rva=mask-self.image.pe.base
            if not any(s['rva']+s['raw_size']<=rva<rva+2<=s['rva']+s['size'] for s in self.image.pe.sections):raise ValueError('Global mask left PE zero-fill region')
            uc.mem_map(mask&~4095,4096,self.u.UC_PROT_READ);self.mask_mapped=True;return True
        return super().map_page(uc,access,address,size,value,extra)

    def stub_return(self,value=0):
        uc,x=self.uc,self.x;rsp=uc.reg_read(x.UC_X86_REG_RSP)
        if not self.base<=rsp<rsp+8<=self.base+0x40000:raise ValueError('Stub stack bound')
        ret=struct.unpack('<Q',uc.mem_read(rsp,8))[0]
        if not any(lo<=ret<hi for lo,hi in self.allowed):raise ValueError('Stub return outside reviewed code')
        uc.reg_write(x.UC_X86_REG_RAX,value);uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,ret)

    def guard(self,uc,address,size,extra):
        x=self.x
        if address==0x1468e4100:
            index=len(self.allocations);requested=uc.reg_read(x.UC_X86_REG_RCX)
            if index>=2 or requested!=[0x430,0x18][index]:raise ValueError('Unexpected base-filter allocation')
            pointer=[self.impl,self.refcounter][index];uc.mem_write(pointer,bytes(requested))
            self.allocations.append(requested);self.events.append(dict(kind='allocate',bytes=requested))
            self.stub_return(pointer);return
        if address==0x1416aaaf0:
            pointer=uc.reg_read(x.UC_X86_REG_RCX);delta=pointer-self.class_base
            if delta<0 or delta%0x180 or delta//0x180>=len(self.area_inputs):raise ValueError('Unexpected CDO creation pointer')
            index=delta//0x180;state=self.area_inputs[index]['class_state']
            if state not in ('create','null_cdo'):raise ValueError('Unexpected CDO creation state')
            if state=='create':uc.mem_write(pointer+0x110,struct.pack('<Q',self.cdo_base+index*0x100))
            self.events.append(dict(kind='cdo_load_stub',record_index=index,provided=state=='create'))
            self.stub_return();return
        if address in (0x145294560,0x145294590):
            self.events.append(dict(kind='travel' if address==0x145294560 else 'entering',
                area_id=uc.reg_read(x.UC_X86_REG_RDX)&255,
                value=struct.unpack('<f',struct.pack('<I',uc.reg_read(x.UC_X86_REG_XMM2)&0xffffffff))[0]))
        super().guard(uc,address,size,extra)

    def initialize(self,areas,owner_5bc,owner_5d0,owner_644,blocked_flags):
        validate_inputs(areas,owner_5bc,owner_5d0,owner_644,blocked_flags)
        uc,x=self.uc,self.x;self.events=[];self.allocations=[];self.setter_calls=[];self.area_inputs=areas
        if not self.mask_mapped:self.map_page(uc,self.u.UC_MEM_READ_UNMAPPED,self.mask_address,2,0,None)
        uc.mem_write(self.mask_address,struct.pack('<H',blocked_flags))
        uc.mem_write(self.owner,bytes(0x800));uc.mem_write(self.shared,bytes(40))
        uc.mem_write(self.owner+0x400,struct.pack('<Q',self.shared))
        uc.mem_write(self.owner+0x460,struct.pack('<QII',self.records,len(areas),len(areas)))
        uc.mem_write(self.owner+0x5bc,struct.pack('<f',float32(owner_5bc)))
        uc.mem_write(self.owner+0x5d0,struct.pack('<I',owner_5d0))
        uc.mem_write(self.owner+0x644,struct.pack('<f',float32(owner_644)))
        for index,area in enumerate(areas):
            cls=self.class_base+index*0x180;cdo=self.cdo_base+index*0x100
            uc.mem_write(cls,bytes(0x180));uc.mem_write(cdo,bytes(0x50))
            uc.mem_write(cdo,struct.pack('<Q',self.area_vtable['table']))
            uc.mem_write(cdo+0x30,struct.pack('<ff',float32(area['travel']),float32(area['entering'])))
            uc.mem_write(cls+0x110,struct.pack('<Q',cdo if area['class_state']=='present' else 0))
            uc.mem_write(self.records+index*32,struct.pack('<16xI4xQ',area['area_id'],0 if area['class_state']=='null_class' else cls))
        self.execute(0x1452b7120,{x.UC_X86_REG_RCX:self.owner})
        if self.allocations!=[0x430,0x18]:raise ValueError('Missing native allocation requests')
        impl,counter=struct.unpack('<QQ',uc.mem_read(self.shared+16,16))
        if (impl,counter)!=(self.impl,self.refcounter):raise ValueError('Native shared-reference move failed')
        return dict(state=dict(**self.snapshot(),owner_5bc_truncated=struct.unpack('<i',uc.mem_read(self.shared+0x20,4))[0],
            impl_flag428=uc.mem_read(self.impl+0x428,1)[0],impl_double410=struct.unpack('<d',uc.mem_read(self.impl+0x410,8))[0]),
            events=list(self.events),reference_counts=list(struct.unpack('<II',uc.mem_read(self.refcounter+8,8))),
            constructor_and_area_loop_executed=True,runtime_verified=False)
