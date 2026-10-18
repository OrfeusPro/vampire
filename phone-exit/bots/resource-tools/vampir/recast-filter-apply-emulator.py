"""Native filter constructor and area override handler on local synthetic objects."""
import hashlib,importlib.util,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('filter_apply_base',HERE/'recast-portal-emulator.py')
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)

class FilterApplyEmulator(parent.PortalEmulator):
    def __init__(self,root=Path('F:/PhoneExit Resources/Vampir')):
        super().__init__(root)
        spec=importlib.util.spec_from_file_location('filter_apply_native',HERE/'build-native-entry-code.py')
        native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
        roots=[0x145282960,0x145281400,0x14526c480,0x145299c20,0x14523af10,0x143850680,0x145294b10]
        self.apply_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in roots})
        self.leaves=[]
        for lo,hi in [(0x14145d5b0,0x14145d5bb),(0x14145ae70,0x14145ae7b),(0x1414532b0,0x1414532bb),
            (0x14385f9c0,0x14385f9cb),(0x14385f9b0,0x14385f9bb),(0x145294560,0x145294585),
            (0x145294590,0x1452945a4),(0x1452945b0,0x1452945db),(0x145294ad0,0x145294ad8),(0x145294af0,0x145294af8)]:
            offset=self.image.offset(lo-self.image.pe.base);raw=self.data[offset:offset+hi-lo]
            cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
            rows=[dict(address=r.address,mnemonic=r.mnemonic,operands=r.op_str,bytes=r.bytes.hex()) for r in cs.disasm(raw,lo)]
            if sum(len(bytes.fromhex(r['bytes'])) for r in rows)!=len(raw):raise ValueError('Changed filter leaf boundary')
            self.leaves.append(dict(begin_rva=lo-self.image.pe.base,end_rva=hi-self.image.pe.base,file_offset=offset,
                sha256=hashlib.sha256(raw).hexdigest(),instructions=rows,leaf_without_pdata=True))
        allowed_roots={0x5282960,0x5299c20,0x523af10}
        self.allowed=[(self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.apply_fragments if f['root_begin_rva'] in allowed_roots]
        self.allowed.extend((self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.leaves)
        self.impl=self.base+0x8000;self.shared=self.base+0x9000;self.cdo=self.base+0xa000;self.owner=self.base+0xb000
        self.records=self.base+0xc000;self.root_class=self.base+0xd000;self.class_base=self.base+0xe000;self.map_elements=self.base+0x18000
        self.static_class_stub_calls=0;self.setter_calls=[];self.apply_calls=0

    def guard(self,uc,address,size,_):
        x=self.x
        if address==0x1452829bd:
            uc.reg_write(x.UC_X86_REG_RAX,self.root_class);uc.reg_write(x.UC_X86_REG_RIP,address+5);self.static_class_stub_calls+=1
        elif address==0x14523af9b:
            destination=uc.reg_read(x.UC_X86_REG_RCX);count=uc.reg_read(x.UC_X86_REG_R8);fill=uc.reg_read(x.UC_X86_REG_RDX)&255
            if destination!=self.impl+0x210 or count!=512 or fill:raise ValueError('Unexpected filter memset')
            uc.mem_write(destination,bytes(count));uc.reg_write(x.UC_X86_REG_RAX,destination);uc.reg_write(x.UC_X86_REG_RIP,address+5)
        elif not any(lo<=address<hi for lo,hi in self.allowed):raise ValueError('Unexpected filter apply code '+hex(address))
        if address in [0x145294560,0x145294590,0x1452945b0,0x145294ad0,0x145294af0]:
            self.setter_calls.append(dict(address=address,area_or_flags=uc.reg_read(x.UC_X86_REG_RDX)&0xffff,
                record_index=uc.reg_read(x.UC_X86_REG_R14D),
                value_float32_bits=(uc.reg_read(x.UC_X86_REG_XMM2)&0xffffffff) if address in [0x145294560,0x145294590] else None))

    def execute(self,address,registers):
        rsp=self.base+0x3f008;self.uc.mem_write(rsp,struct.pack('<Q',self.base));self.uc.reg_write(self.x.UC_X86_REG_RSP,rsp)
        self.uc.reg_write(self.x.UC_X86_REG_MXCSR,0x1f80)
        for reg,value in registers.items():self.uc.reg_write(reg,value)
        self.uc.emu_start(address,self.base,count=2000000)
        if self.uc.reg_read(self.x.UC_X86_REG_RIP)!=self.base:raise ValueError('Filter apply instruction bound')

    def apply(self,areas,area_ids,include_flags=65535,exclude_flags=0):
        if len(areas)>64 or len(area_ids)>64 or len(set(area_ids.values()))!=len(area_ids) or any(not isinstance(i,int) or not 0<=i<64 for i in area_ids.values()):raise ValueError('Invalid area map')
        if any(not isinstance(v,int) or not 0<=v<=65535 for v in [include_flags,exclude_flags]):raise ValueError('Invalid polygon filter flags')
        required={'AreaClass','TravelCostOverride','EnteringCostOverride','bIsExcluded','bOverrideTravelCost','bOverrideEnteringCost'}
        for area in areas:
            if not required<=area.keys():raise ValueError('Omitted area values cannot be inferred')
            if area['AreaClass'] is not None and not isinstance(area['AreaClass'],str):raise ValueError('Invalid area class name')
            if any(not isinstance(area[k],bool) for k in ['bIsExcluded','bOverrideTravelCost','bOverrideEnteringCost']):raise ValueError('Invalid override bool')
            if not all(math.isfinite(area[k]) and abs(area[k])<=3.4028234663852886e38 for k in ['TravelCostOverride','EnteringCostOverride']):raise ValueError('Invalid override float32')
        uc=self.uc;x=self.x;uc.mem_write(self.impl,bytes(0x430));self.setter_calls=[]
        self.execute(0x145299c20,{x.UC_X86_REG_RCX:self.impl,x.UC_X86_REG_RDX:0})
        before=self.snapshot();uc.mem_write(self.shared,bytes(40));uc.mem_write(self.shared+0x10,struct.pack('<Q',self.impl))
        uc.mem_write(self.cdo,bytes(72));uc.mem_write(self.cdo+0x28,struct.pack('<QII',self.records,len(areas),len(areas)))
        uc.mem_write(self.cdo+0x38,struct.pack('<H',include_flags));uc.mem_write(self.cdo+0x3c,struct.pack('<H',exclude_flags))
        uc.mem_write(self.owner,bytes(0x500));uc.mem_write(self.root_class,bytes(0x40))
        names=sorted(set(area_ids)|{a['AreaClass'] for a in areas if a['AreaClass'] is not None})
        if len(names)>64:raise ValueError('Too many synthetic classes')
        classes={name:self.class_base+0x80*i for i,name in enumerate(names)}
        for pointer in classes.values():
            uc.mem_write(pointer,bytes(0x50));uc.mem_write(pointer+0x30,struct.pack('<QI',pointer+0x40,0));uc.mem_write(pointer+0x40,struct.pack('<Q',self.root_class+0x30))
        uc.mem_write(self.owner+0x470,struct.pack('<QII',self.map_elements,len(area_ids),len(area_ids)))
        uc.mem_write(self.owner+0x4a4,struct.pack('<i',0));uc.mem_write(self.owner+0x4a8,struct.pack('<i',0 if area_ids else -1));uc.mem_write(self.owner+0x4b0,bytes(8));uc.mem_write(self.owner+0x4b8,struct.pack('<I',1))
        for index,(name,identifier) in enumerate(sorted(area_ids.items())):
            uc.mem_write(self.map_elements+24*index,struct.pack('<QIIiI',classes[name],identifier,0,index+1 if index+1<len(area_ids) else -1,0))
        for index,area in enumerate(areas):
            flags=int(area['bIsExcluded'])|int(area['bOverrideTravelCost'])<<1|int(area['bOverrideEnteringCost'])<<2
            uc.mem_write(self.records+24*index,struct.pack('<QffB7x',classes.get(area['AreaClass'],0),area['TravelCostOverride'],area['EnteringCostOverride'],flags))
        self.execute(0x145282960,{x.UC_X86_REG_RCX:self.cdo,x.UC_X86_REG_RDX:self.owner,x.UC_X86_REG_R8:0,x.UC_X86_REG_R9:self.shared})
        self.apply_calls+=1
        return dict(before=before,after=self.snapshot(),setter_calls=list(self.setter_calls),base='fresh_native_constructor',runtime_verified=False)

    def snapshot(self):
        return dict(travel_costs=list(struct.unpack('<64d',self.uc.mem_read(self.impl+16,512))),
            entering_costs=list(struct.unpack('<64d',self.uc.mem_read(self.impl+0x210,512))),
            minimum_cost=struct.unpack('<d',self.uc.mem_read(self.impl+0x418,8))[0],
            include_flags=struct.unpack('<H',self.uc.mem_read(self.impl+0x420,2))[0],
            exclude_flags=struct.unpack('<H',self.uc.mem_read(self.impl+0x422,2))[0])
