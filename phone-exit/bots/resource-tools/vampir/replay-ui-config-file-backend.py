"""Native file-attribute backend, constructor leaf and ready base-cache getter; Windows API is a fixture."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('backend_directory',HERE/'replay-ui-config-directory-sources.py')
directory=importlib.util.module_from_spec(spec);spec.loader.exec_module(directory)
native,getter,unicorn,x=directory.native,directory.getter,directory.unicorn,directory.x
ROOTS=(0x1415c6140,0x14144b6b0)
CONSTRUCTOR=0x1414400f0
CTOR_BYTES=bytes.fromhex('488d05e9115b07488901488bc1c3')
SERVICES={0x14157a3e0:'path_allocate_fixture',0x141453890:'path_copy_fixture',0x1415d1540:'path_prepare_fixture',
    0x14156ff70:'path_cleanup_fixture',0x1487e8ce0:'backend_cookie_fixture',0x2004c000:'attributes_fixture'}
COOKIE=0x123456789abcdef0


def validated_sources(image,raw,request,ctor_request):
    for req,roots in ((request,ROOTS),(ctor_request,(CONSTRUCTOR,))):
        if req['source_sha256']!=getter.SHA or req['question']!='ui-nktileview-property-schema' or not {hex(a) for a in roots}<={f['address'] for f in req['functions']}:raise ValueError('Нет explicit backend / constructor того же SHA')
    selected=set()
    for a in ROOTS:
        row=image.containing(a)
        if row is None or image.pe.base+image.roots[row][0]!=a:raise ValueError('Другой backend/cache root')
        selected.add(image.roots[row])
    off=image.offset(CONSTRUCTOR-image.pe.base);next_row=image.containing(CONSTRUCTOR+16)
    if image.containing(CONSTRUCTOR) is not None or raw[off:off+14]!=CTOR_BYTES or raw[off+14:off+16]!=b'\xcc'*2 or next_row is None or image.pe.base+image.roots[next_row][0]!=CONSTRUCTOR+16:raise ValueError('Constructor leaf boundary')
    im=directory.imports(image,raw)
    if im.get('0x14899a5c0',{}).get('name')!='GetFileAttributesW' or im.get('0x14899a4b8',{}).get('name')!='InitializeSRWLock':raise ValueError('Другие imports')
    return native.decode_ranges(image,selected),dict(address=hex(CONSTRUCTOR),bytes=CTOR_BYTES.hex(),padding='cccc',next_unwind_root=hex(CONSTRUCTOR+16),base_vtable='0x1489f12e0'),im['0x14899a5c0']


def read_text(uc,address):
    values=[]
    for n in range(8192):
        v=struct.unpack('<H',uc.mem_read(address+n*2,2))[0]
        if not v:return struct.pack('<'+'H'*len(values),*values).decode('utf-16le')
        values.append(v)
    raise ValueError('Fixture path too long')


def handle_service(uc,address,state,heap):
    q=lambda a:struct.unpack('<Q',uc.mem_read(a,8))[0]
    def ret(value=0):
        sp=uc.reg_read(x.UC_X86_REG_RSP);uc.reg_write(x.UC_X86_REG_RAX,value&0xffffffffffffffff);uc.reg_write(x.UC_X86_REG_RIP,q(sp));uc.reg_write(x.UC_X86_REG_RSP,sp+8)
    rcx,rdx,r8=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
    name=SERVICES[address]
    if name=='path_allocate_fixture':
        if rdx!=state['backend_units'] or q(rcx)!=rcx+0x20 or q(rcx+8)!=q(rcx) or q(rcx+16)!=rcx+0x220 or uc.mem_read(rcx+24,1)[0]!=0:raise ValueError('Backend allocation context/ABI')
        uc.mem_write(rcx,struct.pack('<3Q',heap,heap,heap+(rdx+1)*2));uc.mem_write(rcx+24,bytes([1]));ret()
    elif name=='path_copy_fixture':
        expected=state['expected_backend_path'].encode('utf-16le')
        if r8!=len(expected) or bytes(uc.mem_read(rdx,r8))!=expected:raise ValueError('Backend copy units/source')
        if r8:uc.mem_write(rcx,expected)
        ret(rcx)
    elif name=='path_prepare_fixture':
        if rdx&255!=1 or q(rcx+8)!=q(rcx)+state['backend_units']*2:raise ValueError('Backend prepare ABI/current')
        state['path_context']=rcx;state['path_buffer']=q(rcx);ret()
    elif name=='attributes_fixture':
        if rcx!=state['path_buffer'] or read_text(uc,rcx)!=state['expected_backend_path']:raise ValueError('Attributes input/NUL')
        state['attribute_calls']+=1;ret(state['attributes']&0xffffffff)
    elif name=='path_cleanup_fixture':
        if rcx!=state['path_context'] or q(rcx)!=state['path_buffer'] or q(rcx+8)!=q(rcx)+state['backend_units']*2:raise ValueError('Backend cleanup context')
        state['heap_cleanups']+=int(uc.mem_read(rcx+24,1)[0]!=0);ret()
    else:
        if rcx!=COOKIE:raise ValueError('Backend cookie')
        ret(uc.reg_read(x.UC_X86_REG_RAX))


def run(request,ctor_request):
    if native.capstone.__version__!='5.0.6' or unicorn.__version__!='2.1.4':raise ValueError('Другие инструменты')
    raw=Path(request['source']).read_bytes()
    if getter.sha(raw)!=getter.SHA:raise ValueError('Изменился EXE')
    image=native.Image(raw);fragments,leaf,im=validated_sources(image,raw,request,ctor_request)
    ranges=[(image.pe.base+f['begin_rva'],image.pe.base+f['end_rva']) for f in fragments]+[(CONSTRUCTOR,CONSTRUCTOR+14)]
    pages={p for a,b in ranges for p in range(a&~4095,(b+4095)&~4095,4096)}
    pages.update(a&~4095 for f in fragments for z in f['instructions'] for a in z['rip_references']);pages.update(a&~4095 for a in SERVICES if a>0x140000000)
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page,4096)
        try:off=image.offset(page-image.pe.base)
        except ValueError:continue
        uc.mem_write(page,raw[off:off+4096])
    base=0x20000000;uc.mem_map(base,0x140000)
    inp,heap,obj,stack,stop=[base+a for a in (0x1000,0x10000,0x15000,0x40008,0x48000)]
    uc.mem_write(0x14899a5c0,struct.pack('<Q',0x2004c000));uc.mem_write(0x14b271780,struct.pack('<Q',COOKIE));state={}
    def hook(uc,a,size,_):
        if a==stop:return
        if a in SERVICES:
            state['services'].append(SERVICES[a]);handle_service(uc,a,state,heap);return
        if not any(lo<=a and a+size<=hi for lo,hi in ranges):raise ValueError('Вне backend/cache/constructor '+hex(a))
        if a==0x14144b6e3:raise ValueError('Cache manager initialization excluded')
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    regs=(x.UC_X86_REG_RBX,x.UC_X86_REG_RBP,x.UC_X86_REG_RSI,x.UC_X86_REG_RDI,x.UC_X86_REG_R12,x.UC_X86_REG_R13,x.UC_X86_REG_R14,x.UC_X86_REG_R15)
    def execute(entry,rcx=0,rdx=0):
        uc.mem_write(stack-0x1000,b'\x91'*0x1100);uc.mem_write(stack,struct.pack('<Q',stop));uc.reg_write(x.UC_X86_REG_RSP,stack);uc.reg_write(x.UC_X86_REG_RCX,rcx);uc.reg_write(x.UC_X86_REG_RDX,rdx)
        for n,r in enumerate(regs):uc.reg_write(r,100+n)
        uc.emu_start(entry,stop,count=30000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=stop or uc.reg_read(x.UC_X86_REG_RSP)!=stack+8:raise ValueError('Нет return')
        if [uc.reg_read(r) for r in regs]!=list(range(100,108)):raise ValueError('Nonvolatile')
        return uc.reg_read(x.UC_X86_REG_RAX)
    cases=[]
    paths=(None,'','x','C:'+chr(92)+'Demo'+chr(92)+'file.ini','a'*255,'a'*256,'a'*257,'😀'*127+'x','😀'*128)
    for path,attributes in itertools.product(paths,(-1,0,1,0x10,0x20,0x11,0x80,0x100010)):
        expected=path or '';units=len(expected.encode('utf-16le'))//2
        state.clear();state.update(services=[],expected_backend_path=expected,backend_units=units,attributes=attributes,attribute_calls=0,heap_cleanups=0)
        if path is not None:uc.mem_write(inp,(path+'\0').encode('utf-16le'))
        result=execute(0x1415c6140,obj,inp if path is not None else 0)&255
        if result!=int(attributes!=-1 and not(attributes&0x10)) or state['attribute_calls']!=1 or state['heap_cleanups']!=int(units>=256):raise ValueError('Attributes classification/cleanup')
        if state['services'].count('path_allocate_fixture')!=int(units>=256):raise ValueError('Backend buffer threshold')
        cases.append(dict(path_kind='null' if path is None else 'utf16',path_units=units,attributes_fixture=attributes,result=result,heap=units>=256,services=list(state['services']),complete_return=True))
    constructors=[]
    for target in (obj,obj+0x100,obj+0x200):
        uc.mem_write(target-8,b'\x6a'*24);result=execute(CONSTRUCTOR,target)
        if result!=target or bytes(uc.mem_read(target-8,24))!=b'\x6a'*8+struct.pack('<Q',0x1489f12e0)+b'\x6a'*8:raise ValueError('Constructor leaf output/guards')
        constructors.append(dict(output=hex(target),complete_return=True))
    cached=[]
    uc.mem_write(base+0x58,struct.pack('<Q',base+0x100));uc.mem_write(base+0x100,struct.pack('<Q',base+0x200));uc.mem_write(base+0x200+0x101184,bytes(4));uc.mem_write(0x14b6a4c20,bytes(4));uc.mem_write(0x14b2be0b8,bytes(4));uc.reg_write(x.UC_X86_REG_GS_BASE,base)
    for pointer in (0,obj,0x14b2be048):
        uc.mem_write(0x14b2be0b0,struct.pack('<Q',pointer));state['services']=[]
        if execute(0x14144b6b0)!=pointer or state['services']:raise ValueError('Ready cache getter')
        cached.append(dict(pointer_fixture=hex(pointer),complete_return=True))
    return dict(source_sha256=getter.SHA,fragments=fragments,constructor_leaf=leaf,api_import=im,backend_cases=cases,constructor_cases=constructors,cache_cases=cached,
        limits=['Native file backend; path allocation/copy/prepare/cleanup, GetFileAttributesW and cookie are fixtures; constructor leaf native, cache getter ready branch only.',
            'Attributes are synthetic including impossible input/outcome combinations; no actual file existence, path normalization, OS call, config precedence or UI proof.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--request',type=Path,required=True);p.add_argument('--constructor-request',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('Старый отчёт не перезаписывается')
    r=run(json.loads(a.request.read_text('utf-8')),json.loads(a.constructor_request.read_text('utf-8')));r['replay_sha256']=getter.sha(Path(__file__).read_bytes());a.output.write_text(json.dumps(r,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(backend=len(r['backend_cases']),constructor=len(r['constructor_cases']),cache=len(r['cache_cases']))))
