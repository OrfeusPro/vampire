"""Native user-directory gate/system-folder wrapper; override and fallback roots static only."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('directory_wrapper',HERE/'replay-ui-config-load-wrapper.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
native,getter,unicorn,x=w.native,w.getter,w.unicorn,w.x
ROOTS=(0x141578190,0x141589b30,0x1415d9250,0x141455330)
SERVICES={0x1487e920c:'header',0x1487e91a0:'footer',0x1487e914c:'atexit',0x141533f40:'mode',
    0x14152d5c0:'command_line',0x141584470:'flag',0x141403ab0:'environment',0x141578190:'override',
    0x1415d7dd0:'folder_variant',0x1487dea9d:'known_folder',0x141426b30:'string_copy',
    0x141435320:'replace',0x14142b8a0:'append_slash',0x141483080:'free',0x2004f000:'os_free'}


def imports(image,raw):
    pe=struct.unpack_from('<I',raw,0x3c)[0];rva,_=struct.unpack_from('<II',raw,pe+24+112+8);pos=image.offset(rva);found={}
    while True:
        oft,stamp,chain,name,ft=struct.unpack_from('<5I',raw,pos);pos+=20
        if not any((oft,stamp,chain,name,ft)):break
        no=image.offset(name);dll=raw[no:raw.index(b'\0',no)].decode('ascii')
        for n in range(10000):
            value=struct.unpack_from('<Q',raw,image.offset(oft or ft)+n*8)[0]
            if not value:break
            if value>>63:continue
            vo=image.offset(value)+2;found[hex(image.pe.base+ft+n*8)]=dict(dll=dll,name=raw[vo:raw.index(b'\0',vo)].decode('ascii'))
    return found


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
    fragments=native.decode_ranges(image,selected);im=imports(image,raw)
    if im.get('0x14899b2c0',{}).get('name')!='SHGetKnownFolderPath' or im.get('0x14899c440',{}).get('name')!='CoTaskMemFree':raise ValueError('Другие imports')
    stub=raw[image.offset(0x1487dea9d-image.pe.base):][:6]
    if stub!=bytes.fromhex('ff251dc81b00'):raise ValueError('Другой known-folder thunk')
    literals={}
    for a,t in ((0x148a17040,'UserDir='),(0x148a16818,'SaveToUserDir'),(0x1489e4478,chr(92)),(0x1489f1520,'/'),(0x1489e1b34,'')):
        off=image.offset(a-image.pe.base);encoded=(t+'\0').encode('utf-16le')
        if raw[off:off+len(encoded)]!=encoded:raise ValueError('Другой literal')
        literals[t]=hex(a)
    guids={hex(a):raw[image.offset(a-image.pe.base):image.offset(a-image.pe.base)+16].hex() for a in (0x14a897330,0x14a897370)}
    allowed_roots={0x141589b30-image.pe.base,0x1415d9250-image.pe.base}
    ranges=[(image.pe.base+f['begin_rva'],image.pe.base+f['end_rva']) for f in fragments if f['root_begin_rva'] in allowed_roots]
    pages={p for a,b in ranges for p in range(a&~4095,(b+4095)&~4095,4096)}
    pages.update(a&~4095 for f in fragments for z in f['instructions'] for a in z['rip_references'])
    pages.update(a&~4095 for a in SERVICES if a>0x140000000)
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page,4096)
        try:off=image.offset(page-image.pe.base)
        except ValueError:continue
        uc.mem_write(page,raw[off:off+4096])
    base=0x20000000;uc.mem_map(base,0x140000)
    gs,array,tls,cmd,override_obj,old,os_path,a_data,b_data,c_data,stack,stop=[base+a for a in
        (0,0x1000,0x2000,0x104000,0x105000,0x106000,0x107000,0x108000,0x109000,0x10a000,0x130008,0x138000)]
    uc.mem_write(0x14899c440,struct.pack('<Q',0x2004f000));state={}
    def q(a):return struct.unpack('<Q',uc.mem_read(a,8))[0]
    def d(a):return struct.unpack('<i',uc.mem_read(a,4))[0]
    def ret(value=0):
        sp=uc.reg_read(x.UC_X86_REG_RSP);uc.reg_write(x.UC_X86_REG_RAX,value&0xffffffffffffffff);uc.reg_write(x.UC_X86_REG_RIP,q(sp));uc.reg_write(x.UC_X86_REG_RSP,sp+8)
    def string(obj,data,text):
        encoded=(text+'\0').encode('utf-16le');uc.mem_write(data,encoded);uc.mem_write(obj,struct.pack('<Qii',data,len(encoded)//2,len(encoded)//2))
    def hook(uc,address,size,_):
        if address==stop:return
        if address not in SERVICES:
            if not any(a<=address and address+size<=b for a,b in ranges):raise ValueError('Вне gate/system-dir '+hex(address))
            return
        name=SERVICES[address];state['calls'].append(name)
        rcx,rdx,r8,r9=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        if name in ('header','footer'):
            if rcx!=state['guard']:raise ValueError('Guard ABI')
            uc.mem_write(rcx,struct.pack('<i',-1 if name=='header' and state['initialize'] else 5));ret()
        elif name=='atexit':
            if rcx!=0x148864fe0:raise ValueError('Cleanup target')
            ret()
        elif name=='mode':ret(state['mode'])
        elif name=='command_line':ret(cmd)
        elif name=='flag':
            if (rcx,rdx)!=(cmd,0x148a16818):raise ValueError('Flag ABI')
            ret(state['flag'])
        elif name=='environment':ret(state['environment'])
        elif name=='override':ret(override_obj)
        elif name=='folder_variant':ret(state['variant'])
        elif name=='known_folder':
            if (rcx,rdx,r8)!=(0x14a897330 if state['variant'] else 0x14a897370,0,0):raise ValueError('Known folder ABI')
            if state['hresult']>=0:uc.mem_write(r9,struct.pack('<Q',os_path))
            ret(state['hresult'])
        elif name=='string_copy':
            if rdx!=os_path:raise ValueError('OS string source')
            string(rcx,a_data,'C:'+chr(92)+'Demo');state['copy_object']=rcx;ret(rcx)
        elif name=='replace':
            sp=uc.reg_read(x.UC_X86_REG_RSP)
            if (rcx,r8,r9,d(sp+0x28))!=(state['copy_object'],0x1489e4478,0x1489f1520,1):raise ValueError('Replace ABI')
            string(rdx,b_data,'C:/Demo');state['replace_object']=rdx;ret(rdx)
        elif name=='append_slash':
            if (rdx,r8)!=(state['replace_object'],0x1489f1520):raise ValueError('Append slash ABI')
            string(rcx,c_data,'C:/Demo/');ret(rcx)
        elif name=='free':
            if rcx not in (old,a_data,b_data):raise ValueError('Free pointer')
            state['frees'].append(rcx);ret()
        else:
            if rcx!=os_path:raise ValueError('OS free pointer')
            ret()
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    def start(entry,index,epoch):
        uc.mem_write(gs+0x58,struct.pack('<Q',array));uc.mem_write(array+index*8,struct.pack('<Q',tls));uc.mem_write(tls+0x101184,struct.pack('<i',0));uc.mem_write(0x14b6a4c20,struct.pack('<I',index))
        uc.mem_write(state['guard'],struct.pack('<i',epoch));uc.reg_write(x.UC_X86_REG_GS_BASE,gs)
        uc.mem_write(stack-0x200,b'\x91'*0x300);uc.mem_write(stack,struct.pack('<Q',stop));uc.reg_write(x.UC_X86_REG_RSP,stack)
        preserved=(x.UC_X86_REG_RBX,x.UC_X86_REG_RBP,x.UC_X86_REG_RSI,x.UC_X86_REG_RDI,x.UC_X86_REG_R12,x.UC_X86_REG_R13,x.UC_X86_REG_R14,x.UC_X86_REG_R15)
        for n,r in enumerate(preserved):uc.reg_write(r,100+n)
        uc.emu_start(entry,stop,count=2048)
        if [uc.reg_read(r) for r in preserved]!=list(range(100,108)):raise ValueError('Nonvolatile registers')
        if uc.reg_read(x.UC_X86_REG_RIP)!=stop or uc.reg_read(x.UC_X86_REG_RSP)!=stack+8:raise ValueError('Нет return')
    gate=[]
    for index,mode,flag,env,count in itertools.product((0,2),(0,2),(0,2),(0,2),(0,1,2,8)):
        state.clear();state.update(calls=[],guard=0x14b2f0f4c,initialize=True,mode=mode,flag=flag,environment=env)
        uc.mem_write(override_obj,struct.pack('<Qii',old,count,count));uc.mem_write(0x14b2f0f4a,bytes([77]));start(0x141589b30,index,1)
        expected=['header','mode']
        if not mode:
            expected+=['command_line','flag']
            if not flag:
                expected+=['environment']
                if not env:expected+=['override']
        expected+=['footer'];value=int(bool(mode or flag or env or count>1))
        if state['calls']!=expected or uc.reg_read(x.UC_X86_REG_RAX)!=value or uc.mem_read(0x14b2f0f4a,1)[0]!=value:raise ValueError('Gate short circuit/value')
        gate.append(dict(index=index,mode_fixture=mode,flag_fixture=flag,environment_fixture=env,override_count=count,result=value,services=list(state['calls']),complete_return=True))
    cached=[]
    for value,epoch,index in itertools.product((0,1,2,255),(0,1),(0,2)):
        state.clear();state.update(calls=[],guard=0x14b2f0f4c,initialize=False)
        uc.mem_write(0x14b2f0f4a,bytes([value]));start(0x141589b30,index,epoch)
        if state['calls']!=(['header'] if epoch else []) or uc.reg_read(x.UC_X86_REG_RAX)!=value:raise ValueError('Cached raw byte')
        cached.append(dict(value_fixture=value,guard_epoch=epoch,index=index,complete_return=True))
    folders=[]
    for count,hresult,variant,old_present,initialize in itertools.product((0,1,2,8),(0,-1),(0,2),(False,True),(False,True)):
        state.clear();state.update(calls=[],frees=[],guard=0x14b33f0f0,initialize=initialize,hresult=hresult,variant=variant)
        uc.mem_write(0x14b33f0e0,struct.pack('<Qii',old if old_present else 0,count,99));start(0x1415d9250,0,int(initialize))
        expected=['header','atexit','footer'] if initialize else []
        queried=count<=1;success=queried and hresult>=0
        if queried:expected+=['folder_variant','known_folder']
        if success:expected+=['string_copy','replace','append_slash']+(['free'] if old_present else [])+['free','free','os_free']
        if state['calls']!=expected:raise ValueError('System folder service order')
        expected_data=c_data if success else (old if old_present else 0)
        expected_count=len('C:/Demo/')+1 if success else count
        expected_ptr=expected_data if expected_count else 0x1489e1b34
        if uc.reg_read(x.UC_X86_REG_RAX)!=expected_ptr or q(0x14b33f0e0)!=expected_data or d(0x14b33f0e8)!=expected_count:raise ValueError('System folder transfer/cache')
        if state['frees']!=(([old] if old_present else [])+[b_data,a_data] if success else []):raise ValueError('System folder cleanup')
        folders.append(dict(initial_count=count,hresult_fixture=hresult,variant_fixture=variant,old_data_fixture=old_present,initialize=initialize,queried=queried,success=success,services=list(state['calls']),complete_return=True))
    static_roots={0x141578190,0x141455330}
    static=[]
    for a in static_roots:
        fs=[f for f in fragments if f['root_begin_rva']==a-image.pe.base]
        static.append(dict(address=hex(a),method='static_only_not_executed',calls=[dict(at=hex(z['address']),target=hex(z['direct_target'])) for f in fs for z in f['instructions'] if z['call'] and z['direct_target']]))
    return dict(source_sha256=getter.SHA,fragments=fragments,literals=literals,guids=guids,
        imports={a:im[a] for a in ('0x14899b2c0','0x14899c440')},gate_cases=gate,cached_gate_cases=cached,folder_cases=folders,static_roots=static,
        limits=['Native gate/system-folder wrappers only; TLS/guard, all called predicates, OS API, string/storage/cleanup fixtures.',
            'Override 141578190 and fallback 141455330 inspected statically only; no active directory, actual OS GUID result or precedence proof.',
            'Malformed cache descriptors are synthetic branch probes, not valid FString/lifetime claims.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--request',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('Старый отчёт не перезаписывается')
    r=run(json.loads(a.request.read_text('utf-8')));r['replay_sha256']=getter.sha(Path(__file__).read_bytes())
    a.output.write_text(json.dumps(r,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(gate=len(r['gate_cases']),cached=len(r['cached_gate_cases']),folders=len(r['folder_cases']))))
