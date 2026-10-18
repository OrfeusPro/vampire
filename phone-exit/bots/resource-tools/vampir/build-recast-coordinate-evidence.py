"""Verify and emulate the native world/nav coordinate conversion blocks."""
import hashlib,importlib.util,json,random,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent


def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def main(root=Path('F:/PhoneExit Resources/Vampir')):
    n=load('coordinate_native','build-native-entry-code.py');model=load('coordinate_math','recast-coordinate-math.py')
    import unicorn
    from unicorn import x86_const as x
    if unicorn.__version__!='2.1.4':raise ValueError('Use pinned Unicorn 2.1.4')
    source=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'));data=Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    im=n.Image(data);fragments=n.decode_ranges(im,{im.roots[im.containing(a)] for a in [0x1452b6b30,0x14529c5c0]})
    rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [
        (0x1452b6b69,'mov','r12, r8'),(0x1452b6b7b,'mov','qword ptr [rsp + 0x58], rdx'),
        (0x1452b6c99,'mov','r14, qword ptr [rsp + 0x58]'),
        (0x1452b6ca6,'movsd','xmm1, qword ptr [r12]'),(0x1452b6cac,'xorps','xmm1, xmm6'),
        (0x1452b6cb7,'movsd','xmm0, qword ptr [r14]'),(0x1452b6cbc,'xorps','xmm0, xmm6'),
        (0x1452b6cc3,'movsd','qword ptr [rbp - 0x60], xmm0'),
        (0x1452b6cc8,'movsd','xmm0, qword ptr [r14 + 0x10]'),
        (0x1452b6cce,'movsd','qword ptr [rbp - 0x58], xmm0'),
        (0x1452b6cd3,'movsd','xmm0, qword ptr [r14 + 8]'),(0x1452b6cd9,'xorps','xmm0, xmm6'),
        (0x1452b6ce4,'movsd','qword ptr [rbp - 0x50], xmm0'),
        (0x1452b6cf0,'movsd','qword ptr [rbp - 0x70], xmm0'),
        (0x1452b6cff,'movsd','qword ptr [rbp - 0x78], xmm1'),
        (0x1452b6d04,'movsd','qword ptr [rbp - 0x68], xmm0'),
        (0x1452b6d92,'lea','r9, [rbp - 0x78]'),(0x1452b6d9b,'lea','r8, [rbp - 0x60]'),
        (0x1452b6db1,'call','0x145252290'),
        (0x1452b6db6,'movsd','xmm0, qword ptr [rbp + 0x70]'),
        (0x1452b6dc3,'xorps','xmm0, xmm6'),(0x1452b6dcb,'xorps','xmm1, xmm6'),
        (0x1452b6dce,'unpcklpd','xmm0, xmm1'),(0x1452b6dd5,'movups','xmmword ptr [rdi + 0x610], xmm0'),
        (0x1452b6ddc,'movsd','qword ptr [rdi + 0x620], xmm2'),
        (0x14529c897,'xorps','xmm0, xmm8'),(0x14529c8b5,'movsd','qword ptr [rbp - 0x78], xmm0'),
        (0x14529c8c5,'xorps','xmm0, xmm8'),(0x14529c955,'call','0x145252290'),
    ]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed coordinate anchor '+hex(address))
        anchors.append(row)
    instruction=rows[0x1452b6c91];va=instruction['rip_references'][0];offset=im.offset(va-im.pe.base);mask=data[offset:offset+8]
    if mask!=struct.pack('<Q',1<<63):raise ValueError('Changed sign-bit mask')
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64);base=0x2000000;uc.mem_map(base,0x20000);pages={}
    blocks=[(0x1452b6c91,0x1452b6d09),(0x1452b6db6,0x1452b6de4)]
    def map_page(uc,access,address,size,value,_):
        if access==unicorn.UC_MEM_WRITE_UNMAPPED:return False
        page=address&~4095;off=im.offset(page-im.pe.base);raw=data[off:off+4096]
        if len(raw)!=4096:return False
        uc.mem_map(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC);uc.mem_write(page,raw)
        pages[page]=dict(address=page,file_offset=off,sha256=hashlib.sha256(raw).hexdigest());return True
    def guard(uc,address,size,_):
        if not any(lo<=address<hi for lo,hi in blocks):raise ValueError('Unexpected coordinate code')
    uc.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED,map_page);uc.hook_add(unicorn.UC_HOOK_CODE,guard)
    samples=[[0.,0.,0.],[1.,0.,0.],[0.,1.,0.],[0.,0.,1.],[-0.,-0.,-0.]]
    rng=random.Random(1452)
    samples += [[rng.uniform(-1e6,1e6) for _ in range(3)] for _ in range(64)]
    results=[];rbp=base+0x10000;rsp=base+0x18000;start=base+0x1000;end=base+0x1100;out=base+0x2000
    for sample in samples:
        uc.mem_write(start,struct.pack('<3d',*sample));uc.mem_write(end,struct.pack('<3d',*sample[::-1]));uc.mem_write(rsp+0x58,struct.pack('<Q',start))
        for reg,value in [(x.UC_X86_REG_RBP,rbp),(x.UC_X86_REG_RSP,rsp),(x.UC_X86_REG_R12,end),(x.UC_X86_REG_MXCSR,0x1f80)]:uc.reg_write(reg,value)
        uc.emu_start(*blocks[0],count=100)
        native=bytes(uc.mem_read(rbp-0x60,24));second=bytes(uc.mem_read(rbp-0x78,24))
        if native!=struct.pack('<3d',*model.world_to_nav(sample)) or second!=struct.pack('<3d',*model.world_to_nav(sample[::-1])):raise ValueError('Coordinate model mismatch')
        uc.mem_write(rbp+0x70,native);uc.reg_write(x.UC_X86_REG_RDI,out);uc.emu_start(*blocks[1],count=100)
        inverse=bytes(uc.mem_read(out+0x610,24))
        if inverse!=struct.pack('<3d',*sample):raise ValueError('Inverse coordinate mismatch')
        results.append(dict(world=sample,native_nav=list(struct.unpack('<3d',native)),native_inverse=list(struct.unpack('<3d',inverse))))
    report=dict(source=source['source'],sha256=source['sha256'],fragments=fragments,anchors=anchors,
                sign_mask=dict(address=va,file_offset=offset,bytes=mask.hex()),pages=list(pages.values()),samples=results,
                model_sha256=hashlib.sha256((HERE/'recast-coordinate-math.py').read_bytes()).hexdigest(),
                world_to_nav=['-X','Z','-Y'],nav_to_world=['-X','-Z','Y'],
                limitations=['Coordinate basis only. Candidate archive/runtime selection, link conditions and traversal remain unverified.'])
    path=root/'code-clues/recast-coordinate-evidence.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(anchors),samples=len(results),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__=='__main__':main()
