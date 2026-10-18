"""Bounded offline execution of native portal matching and detail height sampling.

The supplied height parameter and input archive hypotheses remain explicit. No
game process/OS calls. Output capacity is preallocated; only the caller's stack
cookie check is skipped. All matching, triangle math and array count writes run
as client instructions. Synthetic references identify the local target tile only.
"""
import hashlib,importlib.util,json,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
SIDE_STEPS={0:(1,0),1:(1,1),2:(0,1),3:(-1,1),4:(-1,0),5:(-1,-1),6:(0,-1),7:(1,-1)}


def tile_sections(raw):
    if not 88<=len(raw)<=8*1024*1024 or struct.unpack_from('<H',raw)[0]!=7:raise ValueError('Invalid tile buffer')
    u=lambda o:struct.unpack_from('<H',raw,o)[0]
    align=lambda n:(n+7)&~7
    cursor=88;sections={8:0}
    # Native add-tile offsets: verts/polys/links/detail/detail verts/tris/BV/links.
    for pointer,size in [(24,24*u(6)),(16,32*u(4)),(32,16*u(16)),(40,align(6*u(18))),
                         (48,24*u(20)),(56,align(4*u(22))),(64,16*u(24)),(72,80*u(26)),
                         (104,112*u(30)),(112,32*u(36)),(120,align(2*u(18)))]:
        sections[pointer]=cursor;cursor+=size
    if cursor!=len(raw):raise ValueError('Native section sizes do not cover buffer')
    return sections


class PortalEmulator:
    def __init__(self,root=Path('F:/PhoneExit Resources/Vampir')):
        spec=importlib.util.spec_from_file_location('portal_emu_native',HERE/'build-native-entry-code.py')
        n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
        import unicorn
        from unicorn import x86_const as x
        if unicorn.__version__!='2.1.4':raise ValueError('Use pinned Unicorn 2.1.4')
        self.u,self.x=unicorn,x;source=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'))
        self.data=Path(source['source']).read_bytes()
        if hashlib.sha256(self.data).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
        self.image=n.Image(self.data);self.proofs={}
        offset=self.image.offset(0x523cdf0);table=self.data[offset:offset+32]
        if table.hex()!='3fca230543ca230545ca23054aca230551ca230555ca23055bca230559ca2305':raise ValueError('Changed neighbor direction table')
        self.direction_table=dict(address=0x14523cdf0,file_offset=offset,bytes=table.hex(),steps=SIDE_STEPS)
        for name in ['recast-portal-code.json','recast-geometry-code.json']:
            proof_raw=(root/'code-clues'/name).read_bytes();proof=json.loads(proof_raw)
            if proof['sha256']!=source['sha256']:raise ValueError('Changed proof source')
            for f in proof['fragments']:
                off=f['file_offset'];size=f['end_rva']-f['begin_rva']
                if hashlib.sha256(self.data[off:off+size]).hexdigest()!=f['sha256']:raise ValueError('Changed proof fragment')
            self.proofs[name]=hashlib.sha256(proof_raw).hexdigest()
        roots={self.image.roots[self.image.containing(a)] for a in [0x145243d60,0x14524c4d0,0x145240c20,0x145255220]}
        self.fragments=n.decode_ranges(self.image,roots)
        rows={r['address']:r for f in self.fragments for r in f['instructions']}
        if (rows[0x14524441c]['mnemonic'],rows[0x14524441c]['operands'])!=('call','0x148796040'):raise ValueError('Changed cookie call')
        if (rows[0x1452552a6]['mnemonic'],rows[0x1452552a6]['operands'])!=('mov','dword ptr [rcx + 8], ebx'):raise ValueError('Changed array fast path')
        self.allowed=[(self.image.pe.base+f['begin_rva'],self.image.pe.base+f['end_rva']) for f in self.fragments]
        self.uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
        self.base=0x2000000;self.inputs=[0x3000000,0x4000000];self.lengths=[0,0]
        self.uc.mem_map(self.base,0x40000)
        for ptr in self.inputs:self.uc.mem_map(ptr,0x800000,unicorn.UC_PROT_READ)
        self.nav=self.base+0x1000;self.tiles=self.base+0x4000;self.output=self.base+0x6000;self.array=self.base+0x18000
        self.uc.mem_write(self.nav+0xe8,struct.pack('<Q',self.tiles))
        self.uc.mem_write(self.nav+0xf4,struct.pack('<II',16,24))
        self.pages={};self.calls=0;self.height_samples=0;self.triangle_samples=0
        self.uc.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED,self.map_page)
        self.uc.hook_add(unicorn.UC_HOOK_CODE,self.guard)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.write_guard)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_READ,self.read_guard)

    def map_page(self,uc,access,address,size,value,_):
        if access==self.u.UC_MEM_WRITE_UNMAPPED:return False
        page=address&~4095;offset=self.image.offset(page-self.image.pe.base);raw=self.data[offset:offset+4096]
        if len(raw)!=4096:return False
        uc.mem_map(page,4096,self.u.UC_PROT_READ|self.u.UC_PROT_EXEC);uc.mem_write(page,raw)
        self.pages[page]=dict(address=page,file_offset=offset,sha256=hashlib.sha256(raw).hexdigest())
        return True

    def guard(self,uc,address,size,_):
        if address==0x14524441c:uc.reg_write(self.x.UC_X86_REG_RIP,address+5)
        elif not any(lo<=address<hi for lo,hi in self.allowed):raise ValueError('Unexpected native code '+hex(address))
        if address==0x14524c4d0:self.height_samples+=1
        if address==0x145240c20:self.triangle_samples+=1

    def write_guard(self,uc,access,address,size,value,_):
        if not self.base<=address<address+size<=self.base+0x40000:raise ValueError('Native write outside local scratch')

    def read_guard(self,uc,access,address,size,value,_):
        for ptr,length in zip(self.inputs,self.lengths):
            if ptr<=address<ptr+0x800000 and address+size>ptr+length:raise ValueError('Native input read outside tile')

    def load_tiles(self,source,target):
        for i,raw in enumerate([source,target]):
            sections=tile_sections(raw);pointer=self.inputs[i];tile=self.tiles+168*i
            self.lengths[i]=len(raw);self.uc.mem_write(pointer,raw);self.uc.mem_write(tile,bytes(168))
            self.uc.mem_write(tile,struct.pack('<I',1))
            for field,offset in sections.items():self.uc.mem_write(tile+field,struct.pack('<Q',pointer+offset))
        self.source=source;self.target=target

    def match(self,polygon,edge,side,height):
        if side not in [0,2,4,6] or not math.isfinite(height) or height<0:raise ValueError('Unsupported side/height')
        pc,nv=struct.unpack_from('<HH',self.source,4)
        if not 0<=polygon<pc:raise ValueError('Source polygon bound')
        offset=88+24*nv+32*polygon;count=self.source[offset+30]
        if not 1<=count<=6 or not 0<=edge<count:raise ValueError('Source edge bound')
        word=struct.unpack_from('<H',self.source,offset+16+edge*2)[0]
        if word!=0x8000|side:raise ValueError('Source edge side mismatch')
        vertices=[struct.unpack_from('<H',self.source,offset+4+2*j)[0] for j in [edge,(edge+1)%count]]
        if any(v>=nv for v in vertices):raise ValueError('Source vertex bound')
        uc=self.uc;x=self.x;rsp=self.base+0x3f008
        uc.mem_write(self.nav+16,struct.pack('<d',height))
        uc.mem_write(self.output,struct.pack('<QII',self.array,0,4096))
        uc.mem_write(rsp,struct.pack('<Q',self.base))
        for delta,value in [(0x28,polygon),(0x30,self.tiles+168),(0x38,(side-4)&7),(0x40,self.output)]:uc.mem_write(rsp+delta,struct.pack('<Q',value))
        for reg,value in [(x.UC_X86_REG_RSP,rsp),(x.UC_X86_REG_RCX,self.nav),
                          (x.UC_X86_REG_RDX,self.inputs[0]+88+vertices[0]*24),
                          (x.UC_X86_REG_R8,self.inputs[0]+88+vertices[1]*24),
                          (x.UC_X86_REG_R9,self.tiles),(x.UC_X86_REG_MXCSR,0x1f80)]:uc.reg_write(reg,value)
        uc.emu_start(0x145243d60,self.base,count=2000000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=self.base:raise ValueError('Native instruction bound')
        count=struct.unpack('<I',uc.mem_read(self.output+8,4))[0]
        if count!=uc.reg_read(x.UC_X86_REG_RAX) or count>4096:raise ValueError('Result array count mismatch')
        result=[]
        target_count=struct.unpack_from('<H',self.target,4)[0]
        for i in range(count):
            low,high,ref=struct.unpack('<ddQ',uc.mem_read(self.array+24*i,24));index=ref&0xffffff
            if not index<target_count or not math.isfinite(low) or not math.isfinite(high) or high<low:raise ValueError('Invalid native portal result')
            result.append(dict(polygon=index,interval=[low,high]))
        self.calls+=1
        return result

    def provenance(self):
        return dict(proof_sha256=self.proofs,pages=list(self.pages.values()),calls=self.calls,
                    native_detail_height_calls=self.height_samples,native_triangle_height_calls=self.triangle_samples,
                    skipped_cookie_call=0x14524441c,output_capacity=4096,instruction_limit_per_call=2000000,
                    synthetic_tile_references=True,runtime_graph_verified=False,direction_table=self.direction_table)
