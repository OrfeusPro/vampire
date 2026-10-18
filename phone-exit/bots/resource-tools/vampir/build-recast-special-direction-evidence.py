"""Compare flag packing and three direction gates with bounded native blocks."""
import collections,hashlib,importlib.util,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    import unicorn
    from unicorn import x86_const as x
    if unicorn.__version__!='2.1.4':raise ValueError('Use pinned Unicorn 2.1.4')
    native=load('special_direction_native',HERE/'build-native-entry-code.py')
    model=load('special_direction_model',HERE/'recast-special-flags.py')
    source=json.loads((root/'code-clues/native-enums.json').read_bytes());data=Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    image=native.Image(data)
    roots=[0x14523da30,0x14523f590,0x14524faf0,0x1452457b0,0x1452463f0,0x145247ee0]
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in roots})
    rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [
        (0x14523da8d,'test','byte ptr [rdi + 0x4b], 0x40'),
        (0x14523db90,'movzx','ebx, byte ptr [rdi + 0x4b]'),(0x14523db9f,'sar','bl, 7'),
        (0x14523dba7,'and','bl, 0xe0'),(0x14523dbaa,'or','bl, 0xc0'),(0x14523dbb0,'or','dl, 0x10'),
        (0x14523f63b,'sar','r14b, 7'),(0x14523f63f,'and','r14b, 0x20'),
        (0x14523f68f,'test','r8b, 0x40'),(0x14523f7a1,'or','al, 0x40'),
        (0x14523f7b3,'and','al, 0x7f'),(0x14523f7bb,'cmove','ecx, edx'),
        (0x14523f810,'or','al, 0x10'),(0x14523f815,'test','r14b, r14b'),(0x14523f81c,'cmovne','ecx, edx'),
        (0x14524fc18,'mov','byte ptr [r9 + 0xc], al'),(0x14524fc21,'mov','byte ptr [r9 + 0xd], al'),
        (0x145245c0d,'and','al, 0x60'),(0x145245c0f,'cmp','al, 0x40'),
        (0x145245c18,'cmp','byte ptr [rsi + 0x41c], 0'),(0x145245c28,'je','0x145245ccb'),
        (0x14524679c,'and','al, 0x60'),(0x14524679e,'cmp','al, 0x40'),
        (0x1452484eb,'and','al, 0x60'),(0x1452484ed,'cmp','al, 0x40'),
        (0x1452484f6,'cmp','byte ptr [r15 + 0x41c], 0'),(0x145248507,'je','0x1452487f9')]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed anchor '+hex(address))
        anchors.append(row)
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64);base=0x2000000;uc.mem_map(base,0x10000)
    pages={}
    for f in fragments:
        for page in range((image.pe.base+f['begin_rva'])&~4095,(image.pe.base+f['end_rva']+4095)&~4095,4096):
            if page in pages:continue
            offset=image.offset(page-image.pe.base);raw=data[offset:offset+4096]
            uc.mem_map(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC);uc.mem_write(page,raw)
            pages[page]=dict(address=page,file_offset=offset,sha256=hashlib.sha256(raw).hexdigest())
    nav=base+0x1000;record=base+0x2000;filter_pointer=base+0x3000;link=base+0x4000;stack=base+0x8000
    uc.mem_write(nav+0xf8,struct.pack('<I',24));uc.mem_write(record+72,struct.pack('<H',12))
    state={};digest=hashlib.sha256();counts=dict(start_packing=0,end_packing=0,query_gate=0)
    def guard(uc,address,size,_):
        if address in state['stops']:state['stop']=address;uc.emu_stop()
        elif not state['lo']<=address<state['hi']:raise ValueError('Unexpected native instruction '+hex(address))
    def write_guard(uc,access,address,size,value,_):
        if not stack<=address<address+size<=stack+0x100:raise ValueError('Unexpected native write')
    uc.hook_add(unicorn.UC_HOOK_CODE,guard);uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,write_guard)
    def run(lo,hi,registers,stops=()):
        state.update(lo=lo,hi=hi,stops=set(stops),stop=None)
        uc.reg_write(x.UC_X86_REG_RSP,stack)
        for reg,value in registers.items():uc.reg_write(reg,value)
        uc.emu_start(lo,hi,count=200)
        position=uc.reg_read(x.UC_X86_REG_RIP)
        if position!=hi and position not in stops:raise ValueError('Native instruction bound')
        return position
    def check(actual,expected):
        if actual!=expected:raise ValueError(f'Native/model mismatch {actual} != {expected}')
        digest.update(bytes([actual]))
    for flags in range(256):
        uc.mem_write(record+75,bytes([flags]))
        run(0x14523db84,0x14523dbb7,{x.UC_X86_REG_R13:nav,x.UC_X86_REG_RDI:record,x.UC_X86_REG_R14:123})
        check(uc.mem_read(stack+0x28,1)[0],model.metadata(flags,-1,True)['start_to_surface']);counts['start_packing']+=1
        for side in [-1,*range(8)]:
            opposite=0x80 if side==-1 else (side-4)&7
            for same in [False,True]:
                regs={x.UC_X86_REG_R13:nav,x.UC_X86_REG_R14:0x20 if flags&128 else 0,
                      x.UC_X86_REG_RBP:base+0x5000,x.UC_X86_REG_RSI:base+0x5000 if same else base+0x6000,
                      x.UC_X86_REG_RBX:record,x.UC_X86_REG_R8:123}
                uc.mem_write(stack+0xc8,bytes([opposite]));uc.mem_write(stack+0xd8,struct.pack('<i',side))
                run(0x14523f78c,0x14523f7c5,regs)
                check(uc.mem_read(stack+0x28,1)[0],model.metadata(flags,side,same)['end_to_surface'])
                run(0x14523f7d1,0x14523f826,regs)
                check(uc.mem_read(stack+0x28,1)[0],model.metadata(flags,side,same)['surface_to_end']);counts['end_packing']+=2
    for lo,hi,reject,filter_reg in [(0x145245c06,0x145245c2e,0x145245ccb,x.UC_X86_REG_RSI),
        (0x145246795,0x1452467bf,0x14524685e,x.UC_X86_REG_R12),
        (0x1452484e4,0x14524850d,0x1452487f9,x.UC_X86_REG_R15)]:
        for metadata in range(256):
            for reverse in [0,1]:
                uc.mem_write(link+13,bytes([metadata]));uc.mem_write(filter_pointer+0x41c,bytes([reverse]))
                position=run(lo,hi,{x.UC_X86_REG_RAX:link,filter_reg:filter_pointer},[reject])
                check(int(position==hi),int(model.direction_gate(metadata,reverse)));counts['query_gate']+=1
    points_path=root/'maps/navigation-study/special-links/index.json';points_raw=points_path.read_bytes();points=json.loads(points_raw)
    special_proof=(root/'code-clues/recast-special-code.json').read_bytes()
    if hashlib.sha256(special_proof).hexdigest()!=points['native_proof_sha256']['recast-special-code.json']:raise ValueError('Changed special proof')
    histogram=dict(collections.Counter(str(p['flags_raw']) for p in points['links']))
    if histogram!={'192':62}:raise ValueError('Stored point flags changed; review conclusions')
    report=dict(source=source['source'],sha256=source['sha256'],model_sha256=hashlib.sha256((HERE/'recast-special-flags.py').read_bytes()).hexdigest(),
        source_special_report_sha256=hashlib.sha256(points_raw).hexdigest(),point_flags_histogram=histogram,
        anchors=anchors,fragments=fragments,pages=list(pages.values()),native_cases=counts,cases_sha256=digest.hexdigest(),
        observations=['Point flag 0x40 selects the first endpoint search before fallback.',
            'Point flag 0x80 maps to link metadata bit 0x20; all 62 stored special points have flags 0xC0.',
            'Three query loops apply a direction gate only when (metadata & 0x60) == 0x40; bit 0x10 is compared with query field +0x41c.',
            'With point bit 0x80 set, generated endpoint metadata bypasses this direction gate in both directions.'],
        limitations=['Bounded instruction blocks, not full attachment or query execution.',
            'The runtime meaning/configuration of query direction field +0x41c and other polygon/custom filters remain unverified.',
            'No active coverage, attachment nodes, component binding or in-game traversability is proven.'])
    path=root/'code-clues/recast-special-direction-evidence.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(anchors),fragments=len(fragments),native_cases=counts,sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report

if __name__=='__main__':main()
