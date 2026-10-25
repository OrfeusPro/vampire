"""Native flag search/compare, integrity-flag selector and cached installed predicate; optional directory gate."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('predicate_directory',HERE/'replay-ui-config-directory-sources.py')
directory=importlib.util.module_from_spec(spec);spec.loader.exec_module(directory)
native,getter,unicorn,x=directory.native,directory.getter,directory.unicorn,directory.x
ROOTS=(0x141533f40,0x141584470,0x1415d7dd0,0x14145f4a0)
KEYS=('SaveToUserDir','ExpectLowIntegrityLevel','ExpectMediumIntegrityLevel')
PATTERNS=('', '{k}', '-{k}', '/{k}', 'x -{k}', 'x-{k}', '--{k}', '-{k}x','-{k}=1','-{k} ',
    '\t/{k}\n','"-{k}"','a /{k} b','_-{k}','-/{k}',' -{k} -{k}','/{k},','Ж-{k}','-{k}\0junk','-{k}\tX')
FOLDER_TEXTS=('', '-ExpectLowIntegrityLevel','/ExpectLowIntegrityLevel','-ExpectMediumIntegrityLevel',
    '-ExpectLowIntegrityLevel -ExpectMediumIntegrityLevel','-ExpectLowIntegrityLevelx','ExpectLowIntegrityLevel',
    '"-ExpectLowIntegrityLevel"','-expectlowintegritylevel','x -ExpectMediumIntegrityLevel')
GATE_TEXTS=('', '-SaveToUserDir','/SaveToUserDir','SaveToUserDir','-SaveToUserDir=1','"-SaveToUserDir"','x -SaveToUserDir','-savetouserdir')


def oracle(text,key):
    text=text.split('\0')[0];quoted=False;lower=lambda t:''.join(chr(ord(c)+32) if 'A'<=c<='Z' else c for c in t)
    for i,c in enumerate(text):
        if not quoted and c in '-/' and (i==0 or text[i-1] in ' \t\n\r\v\f'):
            start=i+1;end=start+len(key)
            if lower(text[start:end])==lower(key) and (end==len(text) or text[end] in ' \t\n\r\v\f'):return True
        if c=='"':quoted=not quoted
    return False


def run(request,gate_request=None):
    if request['question']!='ui-nktileview-property-schema' or request['source_sha256']!=getter.SHA:raise ValueError('Другой вопрос / SHA')
    if not {hex(a) for a in ROOTS}<={f['address'] for f in request['functions']}:raise ValueError('Нет explicit roots')
    if native.capstone.__version__!='5.0.6' or unicorn.__version__!='2.1.4':raise ValueError('Другие инструменты')
    raw=Path(request['source']).read_bytes()
    if getter.sha(raw)!=getter.SHA:raise ValueError('Изменился EXE')
    image=native.Image(raw);roots=list(ROOTS)
    if gate_request is not None:
        if gate_request['source_sha256']!=getter.SHA or gate_request['question']!=request['question'] or '0x141589b30' not in {f['address'] for f in gate_request['functions']}:raise ValueError('Нет explicit gate того же SHA')
        roots.append(0x141589b30)
    selected=set()
    for a in roots:
        row=image.containing(a)
        if row is None or image.pe.base+image.roots[row][0]!=a:raise ValueError('Другой unwind root')
        selected.add(image.roots[row])
    fragments=native.decode_ranges(image,selected);im=directory.imports(image,raw)
    if im.get('0x14899c1f8',{}).get('name')!='iswspace' or im.get('0x14899a568',{}).get('name')!='GetCommandLineW':raise ValueError('Другие imports')
    literals={}
    for a,t in ((0x148a23c18,KEYS[1]),(0x148a23c48,KEYS[2]),(0x148a16818,KEYS[0]),
            (0x148a0d100,'Engine/Build/InstalledProjectBuild.txt'),(0x148a0d150,'NotInstalled'),(0x148a0d170,'Installed')):
        off=image.offset(a-image.pe.base);encoded=(t+'\0').encode('utf-16le')
        if raw[off:off+len(encoded)]!=encoded:raise ValueError('Другой literal')
        literals[t]=hex(a)
    off=image.offset(0x1489f4400-image.pe.base);table=raw[off:off+128]
    if table!=bytes(n+32 if 65<=n<=90 else n for n in range(128)):raise ValueError('Другой ASCII table')
    ranges=[(image.pe.base+f['begin_rva'],image.pe.base+f['end_rva']) for f in fragments]
    services={0x2004e000:'space',0x2004f000:'get_command_line',0x1487e920c:'header',0x1487e91a0:'footer',
        0x14152d5c0:'command_line',0x141403ab0:'environment_fixture',0x141578190:'override_fixture'}
    pages={p for a,b in ranges for p in range(a&~4095,(b+4095)&~4095,4096)}
    pages.update(a&~4095 for f in fragments for z in f['instructions'] for a in z['rip_references'])
    pages.update(a&~4095 for a in services if a>0x140000000)
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page,4096)
        try:off=image.offset(page-image.pe.base)
        except ValueError:continue
        uc.mem_write(page,raw[off:off+4096])
    base=0x20000000;uc.mem_map(base,0x140000)
    gs,array,tls,inp,key,override_obj,stack,stop=[base+a for a in (0,0x1000,0x2000,0x104000,0x108000,0x109000,0x130008,0x138000)]
    uc.mem_write(0x14899c1f8,struct.pack('<Q',0x2004e000));uc.mem_write(0x14899a568,struct.pack('<Q',0x2004f000));state={}
    def q(a):return struct.unpack('<Q',uc.mem_read(a,8))[0]
    def ret(value=0):
        sp=uc.reg_read(x.UC_X86_REG_RSP);uc.reg_write(x.UC_X86_REG_RAX,value&0xffffffffffffffff);uc.reg_write(x.UC_X86_REG_RIP,q(sp));uc.reg_write(x.UC_X86_REG_RSP,sp+8)
    def hook(uc,a,size,_):
        if a==stop:return
        if a not in services:
            if not any(lo<=a and a+size<=hi for lo,hi in ranges):raise ValueError('Вне predicates/gate '+hex(a))
            if a==0x141584470:state['native_flag_calls']+=1
            if a==0x141533f53:raise ValueError('Cold installed predicate не входит в replay')
            return
        name=services[a];state['services'].append(name);rcx=uc.reg_read(x.UC_X86_REG_RCX)
        if name=='space':
            if rcx>127 and rcx!=0x416:raise ValueError('iswspace вне fixture контракта')
            ret(int(chr(rcx) in ' \t\n\r\v\f'))
        elif name in ('command_line','get_command_line'):ret(inp)
        elif name in ('header','footer'):
            if rcx!=state['guard']:raise ValueError('Guard ABI')
            uc.mem_write(rcx,struct.pack('<i',-1 if name=='header' and state['initialize'] else 5));ret()
        elif name=='environment_fixture':ret(state['environment'])
        else:ret(override_obj)
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    regs=(x.UC_X86_REG_RBX,x.UC_X86_REG_RBP,x.UC_X86_REG_RSI,x.UC_X86_REG_RDI,x.UC_X86_REG_R12,x.UC_X86_REG_R13,x.UC_X86_REG_R14,x.UC_X86_REG_R15)
    def execute(entry,text='',word='',guard=0,initialize=False,index=0,environment=0):
        state.clear();state.update(services=[],native_flag_calls=0,guard=guard,initialize=initialize,environment=environment)
        uc.mem_write(inp,(text+'\0').encode('utf-16le'));uc.mem_write(key,(word+'\0').encode('utf-16le'))
        uc.mem_write(gs+0x58,struct.pack('<Q',array));uc.mem_write(array+index*8,struct.pack('<Q',tls));uc.mem_write(tls+0x101184,struct.pack('<i',0));uc.mem_write(0x14b6a4c20,struct.pack('<I',index))
        if guard:uc.mem_write(guard,struct.pack('<i',int(initialize)))
        uc.reg_write(x.UC_X86_REG_GS_BASE,gs);uc.mem_write(stack,struct.pack('<Q',stop));uc.reg_write(x.UC_X86_REG_RSP,stack)
        uc.reg_write(x.UC_X86_REG_RCX,inp);uc.reg_write(x.UC_X86_REG_RDX,key)
        for n,r in enumerate(regs):uc.reg_write(r,100+n)
        uc.emu_start(entry,stop,count=20000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=stop or uc.reg_read(x.UC_X86_REG_RSP)!=stack+8:raise ValueError('Нет return')
        if [uc.reg_read(r) for r in regs]!=list(range(100,108)):raise ValueError('Nonvolatile')
        return uc.reg_read(x.UC_X86_REG_RAX)&255
    flags=[]
    for word,pattern,lowercase in itertools.product(KEYS,PATTERNS,(False,True)):
        text=pattern.format(k=word.lower() if lowercase else word);expected=oracle(text,word);result=execute(0x141584470,text,word)
        if result!=int(expected):raise ValueError('Flag mismatch '+repr(text))
        flags.append(dict(text_fixture=text,key=word,result=result,complete_return=True))
    folders=[]
    for text,index in itertools.product(FOLDER_TEXTS,(0,2)):
        uc.mem_write(0x14b340540,bytes([77]));result=execute(0x1415d7dd0,text,guard=0x14b340544,initialize=True,index=index)
        low=oracle(text,KEYS[1]);expected_calls=1 if low else 2
        if result!=int(low) or uc.mem_read(0x14b340540,1)[0]!=int(low) or state['native_flag_calls']!=expected_calls:raise ValueError('Folder flag selector')
        folders.append(dict(text_fixture=text,index=index,result=result,native_flag_calls=expected_calls,complete_return=True))
    cached=[]
    for value,index in itertools.product((0,1,2,255),(0,2)):
        uc.mem_write(0x14b340540,bytes([value]));result=execute(0x1415d7dd0,guard=0x14b340544,index=index)
        if result!=value or state['native_flag_calls']:raise ValueError('Cached folder byte')
        cached.append(dict(value_fixture=value,index=index,complete_return=True))
    installed=[]
    for value in (-2,0,1,2,255):
        uc.mem_write(0x14b0c0900,struct.pack('<i',value));result=execute(0x141533f40)
        if result!=int(value==1):raise ValueError('Installed cached predicate')
        installed.append(dict(cache_fixture=value,result=result,complete_return=True))
    gates=[]
    if gate_request is not None:
        for text,mode,env,count in itertools.product(GATE_TEXTS,(0,1),(0,2),(0,2)):
            uc.mem_write(0x14b0c0900,struct.pack('<i',mode));uc.mem_write(override_obj,struct.pack('<Qii',0,count,count));uc.mem_write(0x14b2f0f4a,bytes([77]))
            result=execute(0x141589b30,text,guard=0x14b2f0f4c,initialize=True,environment=env)
            expected=bool(mode or oracle(text,KEYS[0]) or env or count>1)
            if result!=int(expected) or state['native_flag_calls']!=int(not mode):raise ValueError('Whole gate result/flag dispatch')
            gates.append(dict(text_fixture=text,installed_cache_fixture=mode,environment_fixture=env,override_count=count,result=result,native_flag_calls=state['native_flag_calls'],complete_return=True))
    return dict(source_sha256=getter.SHA,fragments=fragments,literals=literals,imports={a:im[a] for a in ('0x14899c1f8','0x14899a568')},
        flag_cases=flags,folder_cases=folders,cached_folder_cases=cached,installed_cached_cases=installed,gate_cases=gates,
        installed_cold_scope='static only: Engine/Build/InstalledProjectBuild.txt / NotInstalled / Installed, filesystem vtable+0x48 and further callees unknown',
        limits=['Native flag/compare/folder selector; iswspace fixture for ASCII plus explicit Ж=>0, GetCommandLineW and TLS/guard fixtures; gate environment/override fixtures.',
            'Installed predicate only native cache!= -1 branch; cold path statically inspected, never executed.',
            'No real command line, actual integrity level, OS directories, precedence or active UI proof.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--request',type=Path,required=True);p.add_argument('--gate-request',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('Старый отчёт не перезаписывается')
    r=run(json.loads(a.request.read_text('utf-8')),json.loads(a.gate_request.read_text('utf-8')) if a.gate_request else None);r['replay_sha256']=getter.sha(Path(__file__).read_bytes())
    a.output.write_text(json.dumps(r,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(flags=len(r['flag_cases']),folders=len(r['folder_cases']),cached=len(r['cached_folder_cases']),installed=len(r['installed_cached_cases']),gates=len(r['gate_cases']))))
