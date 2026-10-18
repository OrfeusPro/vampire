"""Verify AreaBox consumer and bounded offline emulation of its point predicate.

Only selected math bytes and file-backed constants run in Unicorn. No game process,
OS calls, imports, live memory, sockets, or movement. No navigation claim.
"""
import hashlib,importlib.util,json,math,random,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent

def main(root=Path('F:/PhoneExit Resources/Vampir'),reuse=True):
    def load(name,file):
        s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
    n=load('area_native','build-native-entry-code.py');model=load('area_model','area-transform-math.py')
    import unicorn
    from unicorn import x86_const as x
    if unicorn.__version__!='2.1.4':raise ValueError('Pinned Unicorn 2.1.4 required')
    source=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'));exe=Path(source['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    im=n.Image(exe)
    fragments=n.decode_ranges(im,{im.roots[im.containing(a)] for a in [0x145dd3fa0,0x14568ed80,0x145c30150,0x145c38330]})
    rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[];constants=[]
    for a,m,o in [(0x145dd402a,'call','0x145c30150'),(0x145dd406e,'mov','rcx, qword ptr [rbx + 0x10]'),
        (0x145c3016a,'call','0x145c38330'),(0x145c38359,'lea','rax, [rip + 0x5521010]'),
        (0x145dd4087,'call','0x1415892e0'),(0x145dd40bf,'mov','rcx, qword ptr [rbx + 0x20]'),
        (0x145dd40d8,'call','0x1415892e0'),(0x145dd4105,'movss','xmm2, dword ptr [rbx + 0x30]'),
        (0x145dd410a,'lea','rdx, [rsp + 0x28]'),(0x145dd4112,'call','0x14568ed80'),
        (0x14568ee07,'mulss','xmm2, dword ptr [rip + 0x3300001]'),(0x14568ee18,'cvtss2sd','xmm1, xmm2'),
        (0x14568ee1f,'call','0x1487969e0'),(0x14568ee29,'addsd','xmm9, xmm11'),
        (0x14568ee3d,'addsd','xmm13, qword ptr [rbx + 0x18]'),(0x14568ee48,'mulsd','xmm9, xmm8'),
        (0x14568ee52,'mulsd','xmm13, xmm8'),(0x14568ef2e,'subsd','xmm4, xmm9'),
        (0x14568ef41,'subsd','xmm9, xmm13')]:
        r=rows[a]
        if (r['mnemonic'],r['operands'])!=(m,o):raise ValueError('Changed AreaBox anchor '+hex(a))
        anchors.append(r)
    for a,value,fmt in [(0x14568edaa,.5,'d'),(0x14568ee07,model.DEGREES_TO_RADIANS,'f')]:
        off=im.offset(rows[a]['rip_references'][0]-im.pe.base);b=struct.pack('<'+fmt,value)
        if exe[off:off+len(b)]!=b:raise ValueError('Changed AreaBox constant')
        constants.append(dict(file_offset=off,bytes=b.hex(),value=value))
    manager=rows[0x145c38359]['rip_references'][0]
    for a,value in [(manager+8,0x1499ce970),(0x1499ce9a8,0x145c3dae0)]:
        off=im.offset(a-im.pe.base);b=struct.pack('<Q',value)
        if exe[off:off+8]!=b:raise ValueError('Changed AreaBox manager type binding')
        constants.append(dict(file_offset=off,bytes=b.hex(),role='AreaBox manager/loader binding'))
    storage_path=root/'code-clues/area-box-code.json';storage=json.loads(storage_path.read_text('utf-8'))
    if storage['sha256']!=source['sha256']:raise ValueError('Changed AreaBox storage proof')
    anchors+=storage['anchors'];fragments+=storage['fragments']
    for r in anchors:
        b=bytes.fromhex(r['bytes']);off=r['file_offset']
        if exe[off:off+len(b)]!=b:raise ValueError('Changed AreaBox storage anchor')
    math_ranges=[(im.pe.base+f['begin_rva'],im.pe.base+f['end_rva']) for f in fragments if f['root_begin_rva']==0x568ed80]
    trig_ranges=[(0x1487969c0,0x1487969d2),(0x1487969e0,0x148796a29),(0x148797490,0x148797b0b),(0x148797b10,0x14879818f)]
    allowed=math_ranges+trig_ranges
    emu=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64);emu.mem_map(0x2000000,0x20000);emu.mem_map(0x3000000,0x1000);pages={};mapped=set()
    def map_page(uc,access,address,size,value,data):
        if access==unicorn.UC_MEM_WRITE_UNMAPPED:return False
        page=address&~4095
        if page in mapped:return False
        try:off=im.offset(page-im.pe.base)
        except ValueError:return False
        raw=exe[off:off+4096];uc.mem_map(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC);uc.mem_write(page,raw)
        mapped.add(page)
        pages[page]=dict(address=page,file_offset=off,sha256=hashlib.sha256(raw).hexdigest());return True
    def guard(uc,address,size,data):
        if not any(lo<=address<hi for lo,hi in allowed):raise ValueError('Unexpected math code '+hex(address))
    emu.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED,map_page);emu.hook_add(unicorn.UC_HOOK_CODE,guard)
    index=json.loads((root/'maps/atlas/index.json').read_text('utf-8'));table_path=root/'maps/atlas/tables.json';raw=table_path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=index['tables_sha256']:raise ValueError('Changed atlas tables')
    boxes=json.loads(raw)['AreaBox'];rng=random.Random(56880);samples=[]
    model_sha=hashlib.sha256((HERE/'area-transform-math.py').read_bytes()).hexdigest()
    path=root/'code-clues/area-box-transform.json';cached=[]
    if reuse and path.is_file():
        prior=json.loads(path.read_text('utf-8'))
        if prior['model_sha256']==model_sha and prior['tables_sha256']==index['tables_sha256'] and prior['source']['sha256']==source['sha256'] and prior['emulation']['version']==unicorn.__version__:
            if all(hashlib.sha256(exe[p['file_offset']:p['file_offset']+4096]).hexdigest()==p['sha256'] for p in prior['emulation']['pages']):
                cached=prior['emulation']['results']
                pages.update({p['address']:p for p in prior['emulation']['pages']})
    for row in boxes:
        low,high=model.vector(row['AreaBoxMinPos']),model.vector(row['AreaBoxMaxPos'])
        if low is None or high is None or any(a>=b for a,b in zip(low,high)):continue
        samples.append(dict(id=row['Id'],low=low,high=high,yaw=float(row['Yaw'] or 0)))
    samples += [dict(id='asymmetric-'+str(yaw),low=[100.,200.],high=[120.,260.],yaw=yaw) for yaw in [0,30,-30,90,-90,180,270,360]]
    results=[];reused=0
    for sample_index,sample in enumerate(samples):
        low,high,yaw=sample['low'],sample['high'],sample['yaw'];theta=model.angle(yaw);c,s=math.cos(theta),math.sin(theta)
        center=[(a+b)*.5 for a,b in zip(low,high)];extent=[(b-a)*.5 for a,b in zip(low,high)]
        # Away from edges: independently exercises both inside/outside axes and angle direction.
        points=[[center[0]+u*extent[0]*c-v*extent[1]*s,center[1]+u*extent[0]*s+v*extent[1]*c]
                for u,v in [(0,0),(.8,.3),(1.2,.2),(.2,1.2),(-1.2,-.2)]]
        points += [[center[0]+rng.uniform(-2,2)*extent[0],center[1]+rng.uniform(-2,2)*extent[1]] for _ in range(3)]
        expected=[model.contains(p,low,high,yaw) for p in points]
        candidate=cached[sample_index] if sample_index<len(cached) else None
        if candidate==dict(**sample,points=points,contains=expected):
            results.append(candidate);reused+=1;continue
        actual=[]
        for point in points:
            emu.mem_write(0x3000000,struct.pack('<2d',*point));emu.mem_write(0x3000100,struct.pack('<4d',*low,*high))
            rsp=0x2010000-8;emu.mem_write(rsp,struct.pack('<Q',0x2000000))
            for reg,val in [(x.UC_X86_REG_RSP,rsp),(x.UC_X86_REG_RCX,0x3000000),(x.UC_X86_REG_RDX,0x3000100),
                            (x.UC_X86_REG_XMM2,int.from_bytes(struct.pack('<f',yaw),'little')),(x.UC_X86_REG_MXCSR,0x1f80)]:emu.reg_write(reg,val)
            emu.emu_start(0x14568ed80,0x2000000,timeout=2000000,count=10000)
            if emu.reg_read(x.UC_X86_REG_RIP)!=0x2000000:raise ValueError('AreaBox emulation bound reached')
            result=bool(emu.reg_read(x.UC_X86_REG_RAX)&255);expected=model.contains(point,low,high,yaw)
            if result!=expected:raise ValueError('AreaBox formula mismatch '+str(dict(sample=sample,point=point,actual=result,expected=expected)))
            actual.append(result)
        results.append(dict(**sample,points=points,contains=actual))
    report=dict(source=source,anchors=anchors,constants=constants,native_fragments=fragments,
        model_sha256=model_sha,tables_sha256=index['tables_sha256'],
        storage_dependency=dict(file='code-clues/area-box-code.json',sha256=hashlib.sha256(storage_path.read_bytes()).hexdigest()),
        emulation=dict(engine='Unicorn',version=unicorn.__version__,max_instructions=10000,timeout_us=2000000,pages=list(pages.values()),results=results),
        summary=dict(box_samples=len(results),point_samples=sum(len(r['points']) for r in results),reused_identical_samples=reused,rotation_pivot_verified=True,
            rotation_direction_verified=True,pivot='(MinPos+MaxPos)/2',angle='float32(float32(Yaw)*float32(pi/180))',direction='positive XY rotation',navigation_ready=False),
        limitations=['Only XY rectangle geometry; no collision, route, visibility or server-state proof.','Degenerate/inverted boxes not certified by the emulation sample set.'])
    path.write_text(json.dumps(report,ensure_ascii=False,separators=(',',':')),'utf-8');print(json.dumps(report['summary']))

if __name__=='__main__':
    import sys
    main(reuse='--fresh' not in sys.argv)
