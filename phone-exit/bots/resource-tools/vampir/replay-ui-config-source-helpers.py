"""Offline manager and parser wrapper replay; directory-selector body is inspected statically only."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('source_wrapper',HERE/'replay-ui-config-load-wrapper.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
native,getter,unicorn,x=w.native,w.getter,w.unicorn,w.x
ROOTS=(0x14157d1d0,0x141585960,0x14158edf0)
SERVICES={0x1487e920c:'header',0x14156c020:'construct_manager',0x1487e914c:'atexit',0x1487e91a0:'footer',
    0x1487e8c80:'stack_probe',0x1487e8ce0:'cookie',0x141586cf0:'allocate_buffer',0x14158f1a0:'parse_core',
    0x141426b30:'copy_string',0x141427760:'move_string',0x141483080:'free'}
GLOBAL,GUARD,TLS=0x14b2f1190,0x14b2f1198,0x14b6a4c20


def run(request):
    if request['question']!='ui-nktileview-property-schema' or request['source_sha256']!=getter.SHA:raise ValueError('Другой вопрос / SHA')
    if not {hex(a) for a in ROOTS}<={f['address'] for f in request['functions']}:raise ValueError('Нет explicit roots')
    if native.capstone.__version__!='5.0.6' or unicorn.__version__!='2.1.4':raise ValueError('Другие инструменты')
    raw=Path(request['source']).read_bytes()
    if getter.sha(raw)!=getter.SHA:raise ValueError('Изменился EXE')
    image=native.Image(raw);selected=set()
    for a in ROOTS:
        row=image.containing(a)
        if row is None or image.pe.base+image.roots[row][0]!=a:raise ValueError('Другой unwind root')
        selected.add(image.roots[row])
    fragments=native.decode_ranges(image,selected)
    rows={z['address']:z for f in fragments for z in f['instructions']}
    for at,target in ((0x14157d227,0x14156c020),(0x141585969,0x141578190),(0x14158eed3,0x14158f1a0),(0x14158ef08,0x141427760)):
        if rows[at]['direct_target']!=target:raise ValueError('Другой call edge')
    # Directory selector is not executed; keep all chained fragments and exact edges.
    directory=[f for f in fragments if f['root_begin_rva']==0x141585960-image.pe.base]
    directory_calls=[dict(address=hex(z['address']),target=hex(z['direct_target'])) for f in directory for z in f['instructions'] if z['call'] and z['direct_target']]
    ranges=[(image.pe.base+f['begin_rva'],image.pe.base+f['end_rva']) for f in fragments if f not in directory]
    pages={p for a,b in ranges for p in range(a&~4095,(b+4095)&~4095,4096)}
    pages.update(a&~4095 for f in fragments for z in f['instructions'] for a in z['rip_references'])
    pages.update(a&~4095 for a in SERVICES)
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page,4096)
        try:off=image.offset(page-image.pe.base)
        except ValueError:continue
        uc.mem_write(page,raw[off:off+4096])
    base=0x20000000;uc.mem_map(base,0x160000)
    gs,array,tls_block,input_ptr,key,out,heap,temp_data,extra,stack,stop=[base+a for a in
        (0,0x1000,0x2000,0x104000,0x108000,0x109000,0x10a000,0x10d000,0x10e000,0x150008,0x158000)]
    cookie=0x123456789abcdef0;uc.mem_write(0x14b271780,struct.pack('<Q',cookie));state={}
    def q(a):return struct.unpack('<Q',uc.mem_read(a,8))[0]
    def d(a):return struct.unpack('<i',uc.mem_read(a,4))[0]
    def ret(value=0):
        sp=uc.reg_read(x.UC_X86_REG_RSP);uc.reg_write(x.UC_X86_REG_RAX,value)
        uc.reg_write(x.UC_X86_REG_RIP,q(sp));uc.reg_write(x.UC_X86_REG_RSP,sp+8)
    def hook(uc,address,size,_):
        if address==stop:return
        if address not in SERVICES:
            if not any(a<=address and address+size<=b for a,b in ranges):raise ValueError('Вне manager/parser '+hex(address))
            return
        name=SERVICES[address];state['calls'].append(name)
        rcx,rdx,r8,r9=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        sp=uc.reg_read(x.UC_X86_REG_RSP)
        if name in ('header','footer'):
            if rcx!=GUARD:raise ValueError('Другой guard')
            uc.mem_write(GUARD,struct.pack('<i',-1 if name=='header' and state['initialize'] else 5));ret()
        elif name=='construct_manager':
            if rcx!=0x14b2f1068:raise ValueError('Другой static manager storage')
            ret(rcx)
        elif name=='atexit':
            if rcx!=0x148863f20:raise ValueError('Другой manager cleanup target')
            ret()
        elif name=='stack_probe':
            if uc.reg_read(x.UC_X86_REG_RAX)!=0x2070:raise ValueError('Stack probe size')
            ret(0x2070)
        elif name=='allocate_buffer':
            if rdx!=0 or d(rcx+0x2008)!=state['units']+1 or d(rcx+0x200c)!=4096:raise ValueError('Buffer metadata/ABI')
            uc.mem_write(rcx+0x2000,struct.pack('<Q',heap));uc.mem_write(rcx+0x200c,struct.pack('<i',state['units']+1));ret()
        elif name=='parse_core':
            if (rcx,rdx,r9)!=(input_ptr,key,state['units']+1):raise ValueError('Parser core ABI')
            if uc.mem_read(sp+0x28,1)[0]!=state['flag'] or q(sp+0x30)!=state['extra']:raise ValueError('Parser stack args')
            expected=heap if state['units']+1>4096 else sp+8+0x40
            if r8!=expected or bytes(uc.mem_read(r8,2))!=bytes(2):raise ValueError('Parser buffer selection/init')
            state['buffer']=r8;uc.mem_write(r8,state['payload']);ret(state['core_result'])
        elif name=='copy_string':
            if rdx!=state['buffer']:raise ValueError('Temp source')
            state['temporary']=rcx;uc.mem_write(temp_data,state['payload'])
            n=len(state['payload'])//2;uc.mem_write(rcx,struct.pack('<Qii',temp_data,n,n));ret(rcx)
        elif name=='move_string':
            if (rcx,rdx)!=(out,state['temporary']):raise ValueError('Move ABI')
            uc.mem_write(out,bytes(uc.mem_read(rdx,16)))
            if state['clear']:uc.mem_write(rdx,bytes(16))
            ret(out)
        elif name=='free':
            if rcx not in (heap,temp_data):raise ValueError('Другой free')
            state['frees'].append(rcx);ret()
        else:
            if rcx!=cookie:raise ValueError('Cookie')
            ret(uc.reg_read(x.UC_X86_REG_RAX))
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    def start(entry,regs):
        uc.mem_write(stack-0x3000,b'\x91'*0x3100);uc.mem_write(stack,struct.pack('<Q',stop));uc.reg_write(x.UC_X86_REG_RSP,stack)
        for reg,value in regs:uc.reg_write(reg,value)
        uc.reg_write(x.UC_X86_REG_RBX,101)
        uc.emu_start(entry,stop,count=100000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=stop or uc.reg_read(x.UC_X86_REG_RSP)!=stack+8:raise ValueError('Нет return')
        if uc.reg_read(x.UC_X86_REG_RBX)!=101:raise ValueError('RBX')
    manager=[]
    for index,tls_epoch,epoch,initialize in itertools.product((0,2),(-2,0),(0,2),(False,True)):
        if initialize and epoch<=tls_epoch:continue
        state.clear();state.update(calls=[],initialize=initialize)
        uc.mem_write(gs+0x58,struct.pack('<Q',array));uc.mem_write(array+index*8,struct.pack('<Q',tls_block))
        uc.mem_write(tls_block+0x101184,struct.pack('<i',tls_epoch));uc.mem_write(TLS,struct.pack('<I',index))
        uc.mem_write(GUARD,struct.pack('<i',epoch));uc.mem_write(GLOBAL,struct.pack('<Q',extra));uc.reg_write(x.UC_X86_REG_GS_BASE,gs)
        start(0x14157d1d0,[])
        expected=['header','construct_manager','atexit','footer'] if initialize else (['header'] if epoch>tls_epoch else [])
        if state['calls']!=expected or q(GLOBAL)!=(0x14b2f1068 if initialize else extra) or uc.reg_read(x.UC_X86_REG_RAX)!=q(GLOBAL):raise ValueError('Manager order/cache')
        manager.append(dict(index=index,tls_epoch=tls_epoch,guard_epoch=epoch,initialize=initialize,services=list(state['calls']),complete_return=True))
    parser=[]
    for text,flag,core_result,clear,extra_present,payload in itertools.product((None,'','abc','😀','A'*4095,'A'*4096),
            (0,255),(0,2),(False,True),(False,True),('', 'Тест😀')):
        data=(text+'\0').encode('utf-16le') if text is not None else b'';units=len(text.encode('utf-16le'))//2 if text is not None else 0
        state.clear();state.update(calls=[],frees=[],units=units,flag=flag,core_result=core_result,clear=clear,
            extra=extra if extra_present else 0,payload=(payload+'\0').encode('utf-16le'))
        if data:uc.mem_write(input_ptr,data)
        uc.mem_write(key,'-saveddirsuffix=\0'.encode('utf-16le'));uc.mem_write(out-8,b'\x6a'*8+b'\x77'*16+b'\x6b'*8)
        # start resets stack; argument 5 is installed by a register-independent entry hook.
        def entry(uc,a,size,_):
            if a==0x14158edf0:uc.mem_write(stack+0x28,struct.pack('<Q',state['extra']))
        h=uc.hook_add(unicorn.UC_HOOK_CODE,entry)
        start(0x14158edf0,[(x.UC_X86_REG_RCX,input_ptr if text is not None else 0),(x.UC_X86_REG_RDX,key),
            (x.UC_X86_REG_R8,out),(x.UC_X86_REG_R9,flag)])
        uc.hook_del(h)
        success=bool(units and core_result);large=units+1>4096
        expected=['stack_probe']+(['allocate_buffer'] if large else [])+(['parse_core'] if units else [])+(['copy_string','move_string'] if success else [])+(['free'] if success and not clear else [])+(['free'] if large else [])+['cookie']
        if state['calls']!=expected or (uc.reg_read(x.UC_X86_REG_RAX)&255)!=int(success):raise ValueError('Parser order/result')
        expected_frees=([temp_data] if success and not clear else [])+([heap] if large else [])
        if state['frees']!=expected_frees:raise ValueError('Parser cleanup')
        if success:
            n=len(state['payload'])//2
            if bytes(uc.mem_read(out,16))!=struct.pack('<Qii',temp_data,n,n):raise ValueError('Output')
        elif bytes(uc.mem_read(out,16))!=b'\x77'*16:raise ValueError('Failure changed output')
        if bytes(uc.mem_read(out-8,8))!=b'\x6a'*8 or bytes(uc.mem_read(out+16,8))!=b'\x6b'*8:raise ValueError('Output guards')
        parser.append(dict(input_kind='null' if text is None else 'utf16',input_units=units,flag=flag,core_result_fixture=core_result,
            move_clears_fixture=clear,extra_pointer_fixture=extra_present,payload_fixture=payload,large_buffer=large,success=success,services=list(state['calls']),complete_return=True))
    return dict(source_sha256=getter.SHA,fragments=fragments,manager_cases=manager,parser_cases=parser,
        directory_static=dict(method='static_only_not_executed',calls=directory_calls,
            cached_count_gate='141578190 result+8 > 1',branch_gate='141589b30 AL',runtime_text_global='0x14b1d6e70',
            unknown=['141578190 cached source','141589b30 condition','1415d9250/141455330 directory sources','global text runtime value']),
        limits=['Complete native manager/parser wrappers only; TLS/guard/constructor/atexit/stack-probe/core parser/string transfer/allocation/free/cookie fixtures.',
            'Directory selector inspected statically only; no actual parsing, path selection, precedence, process launch or active UI proof.',
            'Successful move semantics synthetic and varied; not proof of 141427760 implementation.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--request',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('Старый отчёт не перезаписывается')
    r=run(json.loads(a.request.read_text('utf-8')));r['replay_sha256']=getter.sha(Path(__file__).read_bytes())
    a.output.write_text(json.dumps(r,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(manager=len(r['manager_cases']),parser=len(r['parser_cases']))))
