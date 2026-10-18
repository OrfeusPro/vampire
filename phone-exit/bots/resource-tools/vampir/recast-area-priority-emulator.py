"""Native cost-sum, sort and rank-copy blocks; explicit local math/memset shims."""
import hashlib,importlib.util,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('priority_portal_base',HERE/'recast-portal-emulator.py')
parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)

def import_at_slot(image,data,slot):
    header=struct.unpack_from('<I',data,60)[0];rva,size=struct.unpack_from('<II',data,header+24+112+8);offset=image.offset(rva)
    for pos in range(offset,offset+size,20):
        original,_,_,name,first=struct.unpack_from('<5I',data,pos)
        if not any([original,name,first]):break
        name_offset=image.offset(name);dll=data[name_offset:data.index(b'\0',name_offset)].decode('ascii');thunk=image.offset(original or first)
        for index in range(10000):
            value=struct.unpack_from('<Q',data,thunk+8*index)[0]
            if not value:break
            if image.pe.base+first+8*index==slot:
                if value>>63:raise ValueError('Ordinal import cannot identify math shim')
                function_offset=image.offset(value)+2
                return dict(dll=dll,name=data[function_offset:data.index(b'\0',function_offset)].decode('ascii'),slot=slot,
                    descriptor_file_offset=pos,thunk_file_offset=thunk+8*index,name_file_offset=function_offset)
    raise ValueError('Priority math import not found')

class AreaPriorityEmulator(parent.PortalEmulator):
    def __init__(self,root=Path('F:/PhoneExit Resources/Vampir')):
        super().__init__(root)
        spec=importlib.util.spec_from_file_location('priority_native',HERE/'build-native-entry-code.py')
        native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
        functions=[0x145240ad0,0x1452b4800,0x142405a70,0x141f830d0]
        self.priority_fragments=native.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in functions})
        lo=0x14523d610;hi=0x14523d63c;offset=self.image.offset(lo-self.image.pe.base);raw=self.data[offset:offset+hi-lo]
        disassembler=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
        rows=[dict(address=r.address,mnemonic=r.mnemonic,operands=r.op_str,bytes=r.bytes.hex()) for r in disassembler.disasm(raw,lo)]
        if not rows or rows[-1]['address']!=hi-1 or rows[-1]['mnemonic']!='ret' or sum(len(bytes.fromhex(r['bytes'])) for r in rows)!=len(raw):raise ValueError('Changed priority leaf bounds')
        self.priority_fragments.append(dict(begin_rva=lo-self.image.pe.base,end_rva=hi-self.image.pe.base,root_begin_rva=lo-self.image.pe.base,
            file_offset=offset,sha256=hashlib.sha256(raw).hexdigest(),instructions=rows,leaf_without_pdata=True))
        self.allowed=[(self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.priority_fragments]
        stub=0x1487a2ecd;stub_offset=self.image.offset(stub-self.image.pe.base);raw_stub=self.data[stub_offset:stub_offset+6]
        if raw_stub[:2]!=b'\xff\x25':raise ValueError('Changed sort math import stub')
        slot=stub+6+struct.unpack_from('<i',raw_stub,2)[0];self.math_import=import_at_slot(self.image,self.data,slot)
        if (self.math_import['dll'],self.math_import['name'])!=('api-ms-win-crt-math-l1-1-0.dll','logf'):raise ValueError('Changed sort math import')
        self.math_import.update(stub=stub,stub_file_offset=stub_offset,stub_bytes=raw_stub.hex())
        self.cost_input=0x5000000;self.uc.mem_map(self.cost_input,4096,self.u.UC_PROT_READ)
        self.shims=[];self.heap_calls=0;self.sort_calls=0

    def read_guard(self,uc,access,address,size,value,_):
        if self.cost_input<=address<self.cost_input+4096 and not self.cost_input+8<=address<address+size<=self.cost_input+0x408:raise ValueError('Native cost read outside arrays')
        super().read_guard(uc,access,address,size,value,_)

    def guard(self,uc,address,size,_):
        x=self.x
        if address==0x142405ac2:
            raw=uc.reg_read(x.UC_X86_REG_XMM0)&0xffffffff
            if raw!=struct.unpack('<I',struct.pack('<f',64.))[0]:raise ValueError('Unexpected logf input')
            result=struct.unpack('<I',struct.pack('<f',math.log(64.)))[0]
            uc.reg_write(x.UC_X86_REG_XMM0,result);uc.reg_write(x.UC_X86_REG_RIP,address+5)
            self.shims.append(dict(kind='logf_64_float32',input_bits=raw,output_bits=result))
        elif address==0x142405ae1:
            destination=uc.reg_read(x.UC_X86_REG_RCX);count=uc.reg_read(x.UC_X86_REG_R8);fill=uc.reg_read(x.UC_X86_REG_RDX)&255
            if fill or count!=0x2e8 or not self.base<=destination<destination+count<=self.base+0x40000:raise ValueError('Unexpected sort memset')
            uc.mem_write(destination,bytes(count));uc.reg_write(x.UC_X86_REG_RAX,destination);uc.reg_write(x.UC_X86_REG_RIP,address+5)
        elif address==0x142405c4c:uc.reg_write(x.UC_X86_REG_RIP,address+5)
        elif not any(lo<=address<hi for lo,hi in self.allowed):raise ValueError('Unexpected priority native code '+hex(address))
        if address==0x141f830d0:self.heap_calls+=1
        if address==0x142405a70:self.sort_calls+=1

    def execute(self,lo,hi,registers):
        for reg,value in registers.items():self.uc.reg_write(reg,value)
        self.uc.emu_start(lo,hi,count=2000000)
        if self.uc.reg_read(self.x.UC_X86_REG_RIP)!=hi:raise ValueError('Priority native instruction bound')

    def constructor_priorities(self):
        self.uc.mem_write(self.nav,bytes([0xa5])*256)
        self.execute(0x145240aee,0x145240b6c,{self.x.UC_X86_REG_RAX:self.nav})
        return list(self.uc.mem_read(self.nav+0x94,64))

    def priorities(self,costs,fixed_costs):
        if len(costs)!=64 or len(fixed_costs)!=64 or not all(math.isfinite(v) for v in (*costs,*fixed_costs)):raise ValueError('Expected 64 finite double costs and fixed costs')
        if not all(math.isfinite(a+b) for a,b in zip(costs,fixed_costs)):raise ValueError('Nonfinite combined area cost')
        uc=self.uc;x=self.x;stack=self.base+0x30000;array=self.base+0x20000;wrapper=self.base+0x10000
        uc.mem_write(self.cost_input,bytes(4096));uc.mem_write(self.cost_input+8,struct.pack('<64d',*costs));uc.mem_write(self.cost_input+0x208,struct.pack('<64d',*fixed_costs))
        uc.mem_write(stack,bytes(0x1000));uc.mem_write(stack+0x28,struct.pack('<QII',array,0,64));uc.mem_write(wrapper+8,struct.pack('<Q',self.nav))
        self.execute(0x1452b4880,0x1452b48d8,{x.UC_X86_REG_RSP:stack,x.UC_X86_REG_R14:self.cost_input,
            x.UC_X86_REG_RBP:0,x.UC_X86_REG_RSI:0,x.UC_X86_REG_MXCSR:0x1f80})
        unsorted=[struct.unpack('<dI4x',uc.mem_read(array+16*i,16)) for i in range(64)]
        if unsorted!=[(a+b,i) for i,(a,b) in enumerate(zip(costs,fixed_costs))]:raise ValueError('Native cost-sum mismatch')
        rsp=self.base+0x3f008;uc.mem_write(rsp,struct.pack('<Q',self.base))
        self.execute(0x142405a70,self.base,{x.UC_X86_REG_RSP:rsp,x.UC_X86_REG_RCX:array,x.UC_X86_REG_RDX:64,
            x.UC_X86_REG_R8:0,x.UC_X86_REG_R9:wrapper,x.UC_X86_REG_MXCSR:0x1f80})
        sorted_rows=[struct.unpack('<dI4x',uc.mem_read(array+16*i,16)) for i in range(64)]
        order=[r[1] for r in sorted_rows]
        if sorted(order)!=list(range(64)) or any(a[0]>b[0] for a,b in zip(sorted_rows,sorted_rows[1:])):raise ValueError('Native area sort failure')
        self.execute(0x1452b4911,0x1452b4948,{x.UC_X86_REG_RSP:stack,x.UC_X86_REG_R15:wrapper,x.UC_X86_REG_RBX:0})
        ranks=list(uc.mem_read(self.nav+0x94,64));expected=[order.index(i) for i in range(64)]
        if ranks!=expected:raise ValueError('Native rank/copy mismatch')
        return dict(costs=list(costs),fixed_costs=list(fixed_costs),sums=[a+b for a,b in zip(costs,fixed_costs)],
            sorted_area_ids=order,ranks=ranks,all_equal_costs=len(set(a+b for a,b in zip(costs,fixed_costs)))==1)
