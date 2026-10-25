"""Whole native cold installed predicate with native path/flag/dispatch helpers; filesystem backend remains fixture."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('installed_predicates',HERE/'replay-ui-config-directory-predicates.py')
pred=importlib.util.module_from_spec(spec);spec.loader.exec_module(pred)
native,getter,unicorn,x=pred.native,pred.getter,pred.unicorn,pred.x
spec=importlib.util.spec_from_file_location('installed_backend',HERE/'replay-ui-config-file-backend.py')
backend=importlib.util.module_from_spec(spec);spec.loader.exec_module(backend)
ROOTS=(0x141533f40,0x141466840,0x141586fe0,0x1415351b0,0x141465720)
PREDICATES=(0x141584470,0x14145f4a0)
FILENAME='Engine/Build/InstalledProjectBuild.txt'
TEXTS=('', '-Installed','-NotInstalled','-Installed -NotInstalled','/Installed','-installed','"-Installed"','-Installed=1')


def run(request,predicate_request,join_request,source_request=None,leaf_request=None,file_request=None,constructor_request=None):
    for req,required in ((request,ROOTS),(predicate_request,PREDICATES),(join_request,(0x1414324d0,))):
        if req['question']!='ui-nktileview-property-schema' or req['source_sha256']!=getter.SHA:raise ValueError('Другой вопрос / SHA')
        if not {hex(a) for a in required}<={f['address'] for f in req['functions']}:raise ValueError('Нет explicit roots')
    if native.capstone.__version__!='5.0.6' or unicorn.__version__!='2.1.4':raise ValueError('Другие инструменты')
    raw=Path(request['source']).read_bytes()
    if getter.sha(raw)!=getter.SHA:raise ValueError('Изменился EXE')
    image=native.Image(raw);selected=set()
    for a in ROOTS+PREDICATES+(0x1414324d0,):
        row=image.containing(a)
        if row is None or image.pe.base+image.roots[row][0]!=a:raise ValueError('Другой unwind root')
        selected.add(image.roots[row])
    chain = source_request is not None or leaf_request is not None
    leaves = {0x141584080:bytes.fromhex('4533c94c8d0596d44607488d15e7034607e97a1eebff'),
        0x1414833a0:bytes.fromhex('488d0509e0e309c3')}
    if chain:
        for req,required in ((source_request,(0x141459960,0x141435f10,0x1414891c0,0x1415ca400)),(leaf_request,tuple(leaves))):
            if req is None or req['source_sha256']!=getter.SHA or req['question']!=request['question'] or not {hex(a) for a in required}<={f['address'] for f in req['functions']}: raise ValueError('Нет explicit source/leaf запроса того же SHA')
        for a in (0x141459960,0x141435f10,0x1414891c0,0x1415ca400):
            row=image.containing(a)
            if row is None or image.pe.base+image.roots[row][0]!=a:raise ValueError('Другой source root')
            selected.add(image.roots[row])
        for a,code in leaves.items():
            off=image.offset(a-image.pe.base)
            if image.containing(a) is not None or raw[off:off+len(code)]!=code or raw[off+len(code):off+len(code)+8]!=b'\xcc'*8:raise ValueError('Другие leaf bytes/padding/boundary')
    fragments=native.decode_ranges(image,selected)
    native_backend=file_request is not None or constructor_request is not None
    ctor_leaf=None;backend_import=None
    if native_backend:
        if not chain or file_request is None or constructor_request is None:raise ValueError('Native backend требует source chain / constructor request')
        backend_fragments,ctor_leaf,backend_import=backend.validated_sources(image,raw,file_request,constructor_request)
        fragments.extend(backend_fragments)
    def fileq(a):return struct.unpack_from('<Q',raw,image.offset(a-image.pe.base))[0]
    if fileq(0x14b0bf650)!=0x1489f7798 or fileq(0x1489f7798+0x48)!=0x141465720:raise ValueError('Другая file-backed dispatch связь')
    literals={}
    for a,t in ((0x148a0d100,FILENAME),(0x148a0d150,'NotInstalled'),(0x148a0d170,'Installed'),
            (0x148a0d860,"Attempting to get the command line but it hasn't been initialized yet."),(0x148a0d338,'LowLevelFatalError')):
        off=image.offset(a-image.pe.base);encoded=(t+'\0').encode('utf-16le')
        if raw[off:off+len(encoded)]!=encoded:raise ValueError('Другой literal')
        literals[t]=hex(a)
    static_root=0x1415351b0-image.pe.base
    ranges=[(image.pe.base+f['begin_rva'],image.pe.base+f['end_rva']) for f in fragments if f['root_begin_rva']!=static_root]
    services={0x141459960:'base_directory',0x141426b30:'copy_string',0x141438050:'reserve',0x1487f5ab9:'copy_bytes',
        0x141584080:'normalize_fixture',0x1414833a0:'platform_manager',0x1414891c0:'platform_resolver',
        0x141483080:'free',0x2004d000:'backend_query',0x2004e000:'space'}
    if chain:
        for a,code in leaves.items():ranges.append((a,a+len(code)))
        for a in (0x141459960,0x141584080,0x1414833a0,0x1414891c0):del services[a]
        services.update({0x14144b6b0:'base_manager_fixture',0x1487f5ad7:'substring_fixture',
            0x1487e920c:'physical_header',0x1487e91a0:'physical_footer',0x1487e914c:'physical_atexit',
            0x1414400f0:'physical_constructor',0x1415c6140:'backend_query'})
        if fileq(0x148a21698+0x78)!=0x1415c6140:raise ValueError('Другая physical vtable slot+78')
    if native_backend:
        ranges.append((backend.CONSTRUCTOR,backend.CONSTRUCTOR+14))
        for a in (0x14144b6b0,0x1414400f0,0x1415c6140):del services[a]
        services.update(backend.SERVICES)
    pages={p for a,b in ranges for p in range(a&~4095,(b+4095)&~4095,4096)}
    pages.update(a&~4095 for f in fragments for z in f['instructions'] for a in z['rip_references'])
    pages.update(a&~4095 for a in services if a>0x140000000);pages.add(0x1489f7798&~4095)
    if chain: pages.update(a&~4095 for a in (0x148a21698,0x1489e4478,0x1489f1520,0x14b2c13b0))
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page,4096)
        try:off=image.offset(page-image.pe.base)
        except ValueError:continue
        uc.mem_write(page,raw[off:off+4096])
    base=0x20000000;uc.mem_map(base,0x140000)
    gs,array,tls,source,storage,manager,platform,table,stack,stop=[base+a for a in
        (0,0x1000,0x2000,0x104000,0x105000,0x106000,0x107000,0x108000,0x130008,0x138000)]
    uc.mem_write(0x14899c1f8,struct.pack('<Q',0x2004e000));uc.mem_write(platform,struct.pack('<Q',table));uc.mem_write(table+0x78,struct.pack('<Q',0x2004d000))
    base_cache=base+0x10b000
    backend_heap=base+0x10e000
    if native_backend:
        uc.mem_write(0x14899a5c0,struct.pack('<Q',0x2004c000));uc.mem_write(0x14b271780,struct.pack('<Q',backend.COOKIE))
    state={}
    def q(a):return struct.unpack('<Q',uc.mem_read(a,8))[0]
    def d(a):return struct.unpack('<i',uc.mem_read(a,4))[0]
    def ret(value=0):
        sp=uc.reg_read(x.UC_X86_REG_RSP);uc.reg_write(x.UC_X86_REG_RAX,value);uc.reg_write(x.UC_X86_REG_RIP,q(sp));uc.reg_write(x.UC_X86_REG_RSP,sp+8)
    def text(a):
        result=[]
        for n in range(1024):
            v=struct.unpack('<H',uc.mem_read(a+n*2,2))[0]
            if not v:return struct.pack('<'+'H'*len(result),*result).decode('utf-16le')
            result.append(v)
        raise ValueError('Too long fixture string')
    def hook(uc,a,size,_):
        if a==stop:return
        if a not in services:
            if not any(lo<=a and a+size<=hi for lo,hi in ranges):raise ValueError('Вне installed/helpers '+hex(a))
            if a==0x141584470:state['flag_calls']+=1
            if a==0x141465720:state['forward_calls']+=1
            if chain and a==0x141584080:
                state['path_object']=uc.reg_read(x.UC_X86_REG_RCX)
                state['normalizer_calls']+=1
            if chain and a==0x1414599a3:raise ValueError('Base directory cold construction excluded')
            if native_backend and a==0x14144b6e3:raise ValueError('Base manager initialization excluded')
            if native_backend and a==backend.CONSTRUCTOR:state['native_constructor_calls']+=1
            if native_backend and a==0x1415c6140:
                rcx=uc.reg_read(x.UC_X86_REG_RCX);rdx=uc.reg_read(x.UC_X86_REG_RDX)
                expected=(state['prefix']+('' if state['prefix'].endswith(('/',chr(92))) else '/')+FILENAME).replace(chr(92),'/')
                if (rcx,rdx)!=(0x14b33e848,q(state['path_object'])) or text(rdx)!=expected:raise ValueError('Native backend entry/path')
                state['queried_path']=expected;state['expected_backend_path']=expected;state['backend_units']=len(expected.encode('utf-16le'))//2
            return
        name=services[a];state['services'].append(name)
        if native_backend and a in backend.SERVICES:
            backend.handle_service(uc,a,state,backend_heap);return
        rcx,rdx,r8=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        if name=='base_manager_fixture':ret(base_cache)
        elif name=='substring_fixture':
            needle=text(rdx);haystack=text(rcx)
            if not needle:raise ValueError('Empty substring outside fixture contract')
            offset=haystack.find(needle)
            ret(rcx+len(haystack[:offset].encode('utf-16le')) if offset>=0 else 0)
        elif name in ('physical_header','physical_footer'):
            if rcx!=0x14b33e850:raise ValueError('Physical guard ABI')
            uc.mem_write(rcx,struct.pack('<i',-1 if name=='physical_header' else 5));ret()
        elif name=='physical_constructor':
            if rcx!=0x14b33e848:raise ValueError('Physical ctor ABI')
            ret(rcx)
        elif name=='physical_atexit':
            if rcx!=0x148864f60:raise ValueError('Physical cleanup ABI')
            ret()
        elif name=='base_directory':ret(source)
        elif name=='copy_string':
            if rdx!=source:raise ValueError('Base source ABI')
            data=(state['prefix']+'\0').encode('utf-16le') if state['prefix'] else b''
            count=len(data)//2;capacity=count+state['extra']
            if data:uc.mem_write(storage,data)
            uc.mem_write(rcx,struct.pack('<Qii',storage if capacity else 0,count,capacity));state['temporary']=rcx;ret(rcx)
        elif name=='reserve':
            if rdx!=d(rcx+8)+(39 if d(rcx+8) else 40) or rdx<=d(rcx+12):raise ValueError('Reserve ABI')
            uc.mem_write(rcx,struct.pack('<Q',storage));uc.mem_write(rcx+12,struct.pack('<i',rdx));ret()
        elif name=='copy_bytes':
            if rdx!=0x148a0d100 or r8!=len(FILENAME)*2:raise ValueError('Join source/counted copy')
            uc.mem_write(rcx,bytes(uc.mem_read(rdx,r8)));ret(rcx)
        elif name=='normalize_fixture':
            state['path_object']=rcx
            expected=state['prefix']+('' if not state['prefix'] or state['prefix'].endswith(('/',chr(92))) else '/')+FILENAME
            if text(q(rcx))!=expected:raise ValueError('Native constructed path')
            ret()
        elif name=='platform_manager':ret(manager)
        elif name=='platform_resolver':
            if rcx!=manager:raise ValueError('Resolver ABI')
            ret(platform)
        elif name=='backend_query':
            expected_platform=0x14b33e848 if chain else platform
            if (rcx,rdx)!=(expected_platform,q(state['path_object'])):raise ValueError('Forwarded query ABI')
            expected=state['prefix']+('' if not state['prefix'] or state['prefix'].endswith(('/',chr(92))) else '/')+FILENAME
            if chain:expected=expected.replace(chr(92),'/')
            if text(rdx)!=expected:raise ValueError('Normalized query path')
            state['queried_path']=text(rdx);ret(state['query_result'])
        elif name=='free':
            if rcx!=storage:raise ValueError('Cleanup pointer')
            state['free_calls']+=1;ret()
        else:
            if rcx>127:raise ValueError('iswspace вне ASCII fixture')
            ret(int(chr(rcx) in ' \t\n\r\v\f'))
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    regs=(x.UC_X86_REG_RBX,x.UC_X86_REG_RBP,x.UC_X86_REG_RSI,x.UC_X86_REG_RDI,x.UC_X86_REG_R12,x.UC_X86_REG_R13,x.UC_X86_REG_R14,x.UC_X86_REG_R15)
    def execute():
        uc.mem_write(stack-0x1000,b'\x91'*0x1100);uc.mem_write(stack,struct.pack('<Q',stop));uc.reg_write(x.UC_X86_REG_RSP,stack)
        for n,r in enumerate(regs):uc.reg_write(r,100+n)
        uc.emu_start(0x141533f40,stop,count=20000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=stop or uc.reg_read(x.UC_X86_REG_RSP)!=stack+8:raise ValueError('Нет return')
        if [uc.reg_read(r) for r in regs]!=list(range(100,108)):raise ValueError('Nonvolatile')
        return uc.reg_read(x.UC_X86_REG_RAX)&255
    cases=[]
    prefixes=('Demo/','Demo','Тест😀','C:'+chr(92)+'Game'+chr(92)) if chain else ('', 'Demo/', 'Demo', 'Тест😀')
    if native_backend:prefixes=prefixes+('a'*250,)
    queries=(-1,0,0x10,0x20) if native_backend else (0,2)
    platform_modes=('resolver_ready','resolver_empty_physical_ready','resolver_empty_physical_init') if chain else ('fixture',)
    for prefix,extra,query,cmd,platform_mode in itertools.product(prefixes,(0,128),queries,TEXTS,platform_modes):
        state.clear();state.update(services=[],flag_calls=0,forward_calls=0,free_calls=0,prefix=prefix,extra=extra,query_result=query,normalizer_calls=0,attributes=query,attribute_calls=0,heap_cleanups=0,native_constructor_calls=0)
        uc.mem_write(source,(prefix+'\0').encode('utf-16le'));uc.mem_write(storage,b'\x91'*512)
        uc.mem_write(gs+0x58,struct.pack('<Q',array));uc.mem_write(array,struct.pack('<Q',tls));uc.mem_write(tls+0x101184,struct.pack('<i',0));uc.mem_write(0x14b6a4c20,bytes(4));uc.reg_write(x.UC_X86_REG_GS_BASE,gs)
        uc.mem_write(0x14b2c1168,bytes(4));uc.mem_write(0x14b0c0900,struct.pack('<i',-1));uc.mem_write(0x14b2c4ca0,bytes([1]));uc.mem_write(0x14b2c4cb0,(cmd+'\0').encode('utf-16le'))
        if chain:
            source_count=len(prefix.encode('utf-16le'))//2+1
            uc.mem_write(base_cache,struct.pack('<Qii',source,source_count,source_count))
            uc.mem_write(0x14b2c13b0,struct.pack('<Q',0x14b33e848 if platform_mode=='resolver_ready' else 0))
            uc.mem_write(0x14b33e848,struct.pack('<Q',0 if platform_mode=='resolver_empty_physical_init' else 0x148a21698))
            uc.mem_write(0x14b33e850,struct.pack('<i',int(platform_mode=='resolver_empty_physical_init')))
        if native_backend:
            uc.mem_write(0x14b2be0b0,struct.pack('<Q',0x14b2be048));uc.mem_write(0x14b2be0b8,bytes(4))
            count=len(prefix.encode('utf-16le'))//2+1;uc.mem_write(0x14b2be048,struct.pack('<Qii',source,count,count))
        query_bool=bool(query!=-1 and not(query&0x10)) if native_backend else bool(query)
        result=execute();expected=not pred.oracle(cmd,'NotInstalled') if query_bool else pred.oracle(cmd,'Installed')
        if result!=int(expected) or d(0x14b0c0900)!=int(expected):raise ValueError('Cold result/cache')
        if state['flag_calls']!=1 or state['forward_calls']!=1 or state['free_calls']!=1:raise ValueError('Native dispatch/cleanup counts')
        if chain:
            if state['normalizer_calls']!=1 or q(0x14b2c13b0)!=0x14b33e848 or q(0x14b33e848)!=0x148a21698 or q(0x148a21698+0x78)!=0x1415c6140:raise ValueError('Native source/normalizer/resolver result')
            constructors=state['native_constructor_calls'] if native_backend else state['services'].count('physical_constructor')
            if constructors!=int(platform_mode=='resolver_empty_physical_init'):raise ValueError('Physical initialization gate')
        if native_backend and (state['attribute_calls']!=1 or state['heap_cleanups']!=int(state['backend_units']>=256)):raise ValueError('Native backend API/cleanup')
        if q(state['temporary'])!=0 or q(state['temporary']+8)!=0:raise ValueError('Moved source not cleared')
        if q(0x14b0bf650)!=0x1489f7798 or q(0x1489f7798+0x48)!=0x141465720:raise ValueError('Static dispatch mutated')
        before=list(state['services']);state['query_result']=0 if query else 2
        if native_backend:state['attributes']=-1 if query_bool else 0
        if execute()!=result or state['services']!=before:raise ValueError('Cached repeat re-ran services')
        cases.append(dict(native_backend=native_backend,attributes_fixture=query if native_backend else None,query_bool=query_bool,platform_mode=platform_mode,normalizer_native=chain,prefix_fixture=prefix,capacity_extra=extra,query_result_fixture=query,command_line_fixture=cmd,
            constructed_path=state['queried_path'],result=result,cached_repeat=True,services=before,complete_return=True))
    return dict(source_sha256=getter.SHA,fragments=fragments,literals=literals,cases=cases,
        native_backend=native_backend,constructor_leaf=ctor_leaf,backend_import=backend_import,native_source_chain=chain,leaves=[dict(address=hex(a),bytes=c.hex(),boundary='explicit bytes + 8 int3; no unwind; normalization tail / manager getter') for a,c in leaves.items()] if chain else [],
        dispatch=dict(object='0x14b0bf650',vtable='0x1489f7798',slot='0x48',target='0x141465720',next_slot='0x78',next_backend='0x1415c6140 native / GetFileAttributesW fixture' if native_backend else ('0x1415c6140 fixture' if chain else 'fixture')),
        diagnostic_scope='1415351b0 static only; uninitialized command line invokes LowLevelFatalError path, not normal initialization; no returning behavior assumed.',
        limits=['Whole native installed predicate plus source-copy wrapper, join, manager getter, first dispatch, flag search/compare; all runs have command-line initialized flag=1.',
            'Without native_source_chain base directory/normalization/platform manager/resolver are fixtures; with it only base-manager cache, substring, constructor/guard/atexit are fixtures in these paths. FString copy/reserve/byte-copy/backend/free/iswspace remain fixtures.',
            'No real file existence, OS command line, actual path/config precedence or active UI proof. With native_backend constructor and ready base-manager getter also native; path prepare/copy/allocation/cleanup/GetFileAttributesW/cookie are fixtures. Base source cold, base-manager init, fatal/errors excluded.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('request','predicate-request','join-request','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--source-request',type=Path);p.add_argument('--leaf-request',type=Path);p.add_argument('--file-request',type=Path);p.add_argument('--constructor-request',type=Path)
    a=p.parse_args()
    if a.output.exists():p.error('Старый отчёт не перезаписывается')
    r=run(json.loads(a.request.read_text('utf-8')),json.loads(a.predicate_request.read_text('utf-8')),json.loads(a.join_request.read_text('utf-8')),json.loads(a.source_request.read_text('utf-8')) if a.source_request else None,json.loads(a.leaf_request.read_text('utf-8')) if a.leaf_request else None,json.loads(a.file_request.read_text('utf-8')) if a.file_request else None,json.loads(a.constructor_request.read_text('utf-8')) if a.constructor_request else None);r['replay_sha256']=getter.sha(Path(__file__).read_bytes())
    a.output.write_text(json.dumps(r,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(cases=len(r['cases']))))
