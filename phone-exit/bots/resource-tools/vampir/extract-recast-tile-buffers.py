"""Bounded offline codec emulation with an explicitly hypothetical custom version.

No game process, OS calls or live memory. Native allocation and archive callbacks
are replaced by bounded local memory operations. Outputs remain candidate buffers;
full byte consumption does not prove the runtime archive version or walkability.
"""
import argparse,hashlib,importlib.util,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('recast_buffer_native',HERE/'build-native-entry-code.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
import unicorn
from unicorn import x86_const as x

ROOT=n.ROOT
pack=struct.pack
unpack=struct.unpack

def run(raw,custom,im,d,fragments):
    if len(raw)>0x1000000 or len(raw)<34:raise ValueError('Export input bounds')
    # This offset is an explicit hypothesis from the envelope report, not a schema.
    version,length,count=struct.unpack_from('<iQi',raw,14)
    if version!=26 or length!=len(raw)-18 or not 0<count<=100000:raise ValueError('Unsupported candidate envelope')
    allowed=[(im.pe.base+f['begin_rva'],im.pe.base+f['end_rva']) for f in fragments]
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    base=0x2000000; input_base=0x3000000; arena=0x4000000
    uc.mem_map(base,0x20000);uc.mem_map(input_base,0x1000000);uc.mem_map(arena,0x2000000)
    archive=base+0x1000;state=base+0x2000;vtable=base+0x3000;container=base+0x4000
    output=base+0x5000;end=base;rawcopy=base+0x80;getversions=base+0x90
    uc.mem_write(input_base,raw)
    uc.mem_write(archive,pack('<QQ',vtable,state));uc.mem_write(archive+0x28,b'\x01')
    uc.mem_write(state,pack('<QQ',input_base+34,input_base+len(raw)))
    uc.mem_write(vtable+0x170,pack('<Q',rawcopy));uc.mem_write(vtable+0x58,pack('<Q',getversions))
    uc.mem_write(container,pack('<Qii',container+0x100,1,1))
    uc.mem_write(container+0x100,bytes.fromhex('86181d60844f64acded316aad6c7ea0d')+pack('<i',custom)+bytes(20))
    allocated=[];next_alloc=arena;pages={};hook_counts={};buffers=[];buffer_offset=0
    def ret(value=None):
        if value is not None:uc.reg_write(x.UC_X86_REG_RAX,value)
        rsp=uc.reg_read(x.UC_X86_REG_RSP)
        target=unpack('<Q',uc.mem_read(rsp,8))[0]
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8);uc.reg_write(x.UC_X86_REG_RIP,target)
    def guard(uc,address,size,_):
        nonlocal next_alloc
        if address in [0x145240ab0,0x1487a2e25,rawcopy,getversions]:
            hook_counts[hex(address)]=hook_counts.get(hex(address),0)+1
            rcx=uc.reg_read(x.UC_X86_REG_RCX);rdx=uc.reg_read(x.UC_X86_REG_RDX);r8=uc.reg_read(x.UC_X86_REG_R8)
            if address==0x145240ab0:
                if not 0<rcx<=8*1024*1024 or next_alloc+rcx>arena+0x2000000:raise ValueError('Allocation bounds')
                ptr=next_alloc;next_alloc=(next_alloc+rcx+15)&~15;allocated.append((ptr,rcx));ret(ptr)
            elif address==0x1487a2e25:
                if not any(p<=rcx and rcx+r8<=p+s for p,s in allocated):raise ValueError('Memset bounds')
                uc.mem_write(rcx,bytes([rdx&255])*r8);ret(rcx)
            elif address==rawcopy:
                cursor,stop=unpack('<QQ',uc.mem_read(state,16))
                if rcx!=archive or not 0<=r8<=8*1024*1024 or cursor+r8>stop:raise ValueError('Archive read bounds')
                if not (base<=rdx and rdx+r8<=base+0x20000 or any(p<=rdx and rdx+r8<=p+s for p,s in allocated)):raise ValueError('Read destination')
                uc.mem_write(rdx,bytes(uc.mem_read(cursor,r8)));uc.mem_write(state,pack('<Q',cursor+r8));ret()
            else:
                if rcx!=archive:raise ValueError('Wrong archive')
                ret(container)
        elif not any(lo<=address<hi for lo,hi in allowed):raise ValueError('Unexpected code '+hex(address))
    def map_page(uc,access,address,size,value,_):
        if access==unicorn.UC_MEM_WRITE_UNMAPPED:return False
        page=address&~4095
        offset=im.offset(page-im.pe.base);chunk=d[offset:offset+4096]
        if len(chunk)!=4096:return False
        uc.mem_map(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC);uc.mem_write(page,chunk);pages[page]=offset
        return True
    def write_guard(uc,access,address,size,value,_):
        if not (base<=address and address+size<=base+0x20000 or
                any(p<=address and address+size<=p+s for p,s in allocated)):
            raise ValueError('Unexpected native write '+hex(address))
    uc.hook_add(unicorn.UC_HOOK_CODE,guard);uc.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED,map_page)
    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,write_guard)
    def call(address):
        rsp=base+0x18008;uc.mem_write(rsp,pack('<Q',end))
        for reg,val in [(x.UC_X86_REG_RSP,rsp),(x.UC_X86_REG_RCX,archive),(x.UC_X86_REG_RDX,26),(x.UC_X86_REG_R8,output),(x.UC_X86_REG_R9,output+8),(x.UC_X86_REG_MXCSR,0x1f80)]:uc.reg_write(reg,val)
        uc.emu_start(address,end,count=1000000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=end:raise ValueError('Instruction bound')
        ptr,size=unpack('<Qi',uc.mem_read(output,12));return ptr,size
    records=[]
    uc.mem_write(state,pack('<Q',input_base+30))
    for i in range(count):
        start=unpack('<Q',uc.mem_read(state,8))[0];memory_size=unpack('<i',uc.mem_read(start,4))[0]
        uc.mem_write(state,pack('<Q',start+4));uc.mem_write(output,pack('<Qi',0,memory_size))
        ptr,size=call(0x1452ba8b0)
        after=unpack('<Q',uc.mem_read(state,8))[0]
        if size!=memory_size or not any(p==ptr and s==size for p,s in allocated):raise ValueError('Native tile buffer size mismatch')
        tile=bytes(uc.mem_read(ptr,size))
        uc.mem_write(output,bytes(12));cacheptr,cachesize=call(0x1452ba2a0)
        stop=unpack('<Q',uc.mem_read(state,8))[0]
        if cacheptr or cachesize:raise ValueError('Nonempty cache requires a separately preserved buffer')
        records.append(dict(index=i,start=start-input_base,end=stop-input_base,stream_tile_bytes=after-start-4,stored_memory_size=memory_size,actual_memory_size=size,buffer_offset=buffer_offset,header=tile[:88].hex(),cache_memory_size=cachesize,tile_sha256=hashlib.sha256(tile).hexdigest()))
        buffers.append(tile);buffer_offset+=size
        next_alloc=arena;allocated.clear()
    if stop-input_base!=len(raw):raise ValueError('Trailing or missing candidate stream bytes')
    return dict(custom_version_hypothesis=custom,property_offset_hypothesis=14,
                records=records,bytes_consumed=stop-input_base,export_size=len(raw),count=count,
                hooks=hook_counts,pages=[dict(address=p,file_offset=o,sha256=hashlib.sha256(d[o:o+4096]).hexdigest()) for p,o in sorted(pages.items())],
                runtime_archive_version_verified=False,polygons_decoded=False),b''.join(buffers)

def main(custom):
    if unicorn.__version__!='2.1.4':raise ValueError('Use pinned Unicorn 2.1.4')
    source=json.loads((ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    data=Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256']:raise ValueError('Changed client EXE')
    image=n.Image(data)
    proof_path=ROOT/'code-clues/recast-serialization-code.json';proof_bytes=proof_path.read_bytes();proof=json.loads(proof_bytes)
    if proof['sha256']!=source['sha256']:raise ValueError('Changed codec proof source')
    for f in proof['fragments']:
        offset=f['file_offset'];size=f['end_rva']-f['begin_rva']
        if hashlib.sha256(data[offset:offset+size]).hexdigest()!=f['sha256']:raise ValueError('Changed proof fragment')
    roots={image.roots[image.containing(a)] for a in [0x1452ba8b0,0x1452ba2a0,0x141597dd0,0x14159a480]}
    fragments=n.decode_ranges(image,roots)
    index_path=ROOT/'maps/navigation-study/generated-chunks/index.json';index_bytes=index_path.read_bytes();index=json.loads(index_bytes)
    if hashlib.sha256(index_bytes).hexdigest()!=proof['generated_source_sha256']:raise ValueError('Changed generated index')
    out=ROOT/'maps/navigation-study'/('tile-buffer-hypothesis-'+str(custom));out.mkdir(exist_ok=True)
    results=[]
    for package in index['packages']:
        for entry in package['navigation_exports']:
            if entry['export']['type']!='RecastNavMeshDataChunk':continue
            raw=(index_path.parent/entry['file']).read_bytes()
            if hashlib.sha256(raw).hexdigest()!=entry['export']['sha256']:raise ValueError('Changed export')
            result,buffers=run(raw,custom,image,data,fragments)
            name=entry['file'].removesuffix('.bin')+'-buffers.bin';(out/name).write_bytes(buffers)
            results.append(dict(source_file=entry['file'],source_export=entry['export'],archive=package['archive'],
                                package=package['package_identity'],buffer_file=name,buffer_sha256=hashlib.sha256(buffers).hexdigest(),**result))
            print(json.dumps(dict(packages=len(results),tiles=result['count'],bytes=result['bytes_consumed'])),flush=True)
    report=dict(source=source,serialization_proof_sha256=hashlib.sha256(proof_bytes).hexdigest(),
                generated_index_sha256=hashlib.sha256(index_bytes).hexdigest(),unicorn_version=unicorn.__version__,packages=results,
                summary=dict(packages=len(results),candidate_tiles=sum(p['count'] for p in results),
                             candidate_buffer_bytes=sum(sum(t['actual_memory_size'] for t in p['records']) for p in results),
                             routes_verified=0,navigation_ready=False),
                assumptions=dict(property_offset=14,custom_version=custom,archive_loading_flags=1,little_endian=True),
                limitations=['Explicit version/property-boundary hypotheses, not verified runtime archive metadata.',
                             'Only bounded local allocator/memset/archive callbacks replace native effects.',
                             'All stored package versions retained; no active version, graph, polygon or traversal claim.'])
    path=out/'index.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=hashlib.sha256(path.read_bytes()).hexdigest())))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--custom-version',type=int,required=True)
    args=parser.parse_args();main(args.custom_version)
