"""Native parameter parser/search/compare with optional native wrapper on the same memory."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('parser_wrapper',HERE/'replay-ui-config-load-wrapper.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
native,getter,unicorn,x=w.native,w.getter,w.unicorn,w.x
ROOTS=(0x14158f1a0,0x14145f4a0)
KEY='-saveddirsuffix='
SERVICES={0x1487f5ad7:'find_quote',0x1487f5ab9:'copy',0x1487e8c80:'probe',0x1487e8ce0:'cookie',
    0x141586cf0:'allocate',0x141426b30:'string_copy',0x141427760:'string_move',0x141483080:'free'}
TEXTS=(None,'','nothing',KEY,KEY+'abc',KEY.upper()+'ABC',KEY+'one two',KEY+'one,two)end',KEY+'  a',
    KEY+'\t\r\nvalue',KEY+'"hello world" tail',KEY+'""',KEY+'"unclosed value',KEY+' "spaced quote"',
    'x'+KEY+'bad','0'+KEY+'bad','_'+KEY+'good','.'+KEY+'good','"'+KEY+'hidden"',
    '"hidden" '+KEY+'visible',KEY+'first '+KEY+'second',KEY+'😀Ж',KEY+'A\0B','prefix\0'+KEY+'hidden',
    KEY+'"a,b)c"',KEY+'"a"b',KEY+'a\tb',KEY+'\r\n',KEY+'a\"b',KEY+'a\\b')


def units(text):
    raw=text.encode('utf-16le');return list(struct.unpack('<'+'H'*(len(raw)//2),raw))


def oracle(text,flag):
    if text is None:return False,[],None
    source=units(text);source=source[:source.index(0)] if 0 in source else source
    key=units(KEY);fold=lambda v:v+32 if 65<=v<=90 else v
    quoted=False
    for i,c in enumerate(source):
        previous=source[i-1] if i else 0
        word=48<=previous<=57 or 65<=previous<=90 or 97<=previous<=122
        if not quoted and not word and [fold(v) for v in source[i:i+len(key)]]==[fold(v) for v in key]:
            start=i+len(key)
            if start<len(source) and source[start]==34:
                start+=1;end=source.index(34,start) if 34 in source[start:] else len(source)
                return True,source[start:end],end+int(end<len(source) and source[end]==34)
            while start<len(source) and source[start] in (32,13,10,9):start+=1
            end=start;delims=(44,41,32,13,10,9) if flag else (32,13,10,9)
            while end<len(source) and source[end] not in delims:end+=1
            return True,source[start:end],end
        if c==34:quoted=not quoted
    return False,[],None


def run(request,wrapper_request=None):
    if request['question']!='ui-nktileview-property-schema' or request['source_sha256']!=getter.SHA:raise ValueError('Другой вопрос / SHA')
    if not {hex(a) for a in ROOTS}<={f['address'] for f in request['functions']}:raise ValueError('Нет explicit core/compare')
    if native.capstone.__version__!='5.0.6' or unicorn.__version__!='2.1.4':raise ValueError('Другие инструменты')
    raw=Path(request['source']).read_bytes()
    if getter.sha(raw)!=getter.SHA:raise ValueError('Изменился EXE')
    image=native.Image(raw);roots=list(ROOTS)
    if wrapper_request is not None:
        if wrapper_request['source_sha256']!=getter.SHA or wrapper_request['question']!=request['question'] or '0x14158edf0' not in {f['address'] for f in wrapper_request['functions']}:raise ValueError('Нет explicit wrapper того же SHA')
        roots.append(0x14158edf0)
    selected=set()
    for a in roots:
        row=image.containing(a)
        if row is None or image.pe.base+image.roots[row][0]!=a:raise ValueError('Другой unwind root')
        selected.add(image.roots[row])
    fragments=native.decode_ranges(image,selected)
    literals={}
    for a,t in ((0x1489e4474,'"'),(0x148a16718,' \r\n\t'),(0x148a16728,',) \r\n\t')):
        off=image.offset(a-image.pe.base);encoded=(t+'\0').encode('utf-16le')
        if raw[off:off+len(encoded)]!=encoded:raise ValueError('Другой delimiter literal')
        literals[t]=hex(a)
    off=image.offset(0x1489f4400-image.pe.base);table=raw[off:off+128]
    if table!=bytes(v+32 if 65<=v<=90 else v for v in range(128)):raise ValueError('Другая ASCII compare table')
    ranges=[(image.pe.base+f['begin_rva'],image.pe.base+f['end_rva']) for f in fragments]
    pages={p for a,b in ranges for p in range(a&~4095,(b+4095)&~4095,4096)}
    pages.update(a&~4095 for f in fragments for z in f['instructions'] for a in z['rip_references'])
    pages.update(a&~4095 for a in SERVICES)
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page,4096)
        try:off=image.offset(page-image.pe.base)
        except ValueError:continue
        uc.mem_write(page,raw[off:off+4096])
    base=0x20000000;uc.mem_map(base,0x50000)
    inp,key,out,endptr,heap,temp,stack,stop=[base+a for a in (0x1000,0x10000,0x11000,0x12000,0x14000,0x18000,0x40008,0x48000)]
    cookie=0x123456789abcdef0;uc.mem_write(0x14b271780,struct.pack('<Q',cookie));uc.mem_write(key,(KEY+'\0').encode('utf-16le'));state={}
    def q(a):return struct.unpack('<Q',uc.mem_read(a,8))[0]
    def d(a):return struct.unpack('<i',uc.mem_read(a,4))[0]
    def readz(a):
        data=[]
        for n in range(8192):
            v=struct.unpack('<H',uc.mem_read(a+n*2,2))[0]
            if v==0:return data
            data.append(v)
        raise ValueError('Fixture string too long')
    def packed(values):return struct.pack('<'+'H'*len(values),*values)
    def ret(value=0):
        sp=uc.reg_read(x.UC_X86_REG_RSP);uc.reg_write(x.UC_X86_REG_RAX,value);uc.reg_write(x.UC_X86_REG_RIP,q(sp));uc.reg_write(x.UC_X86_REG_RSP,sp+8)
    def hook(uc,address,size,_):
        if address==stop:return
        if address not in SERVICES:
            if not any(a<=address and address+size<=b for a,b in ranges):raise ValueError('Вне core/compare/wrapper '+hex(address))
            if address==0x14158f1a0:state['core_calls']+=1
            return
        name=SERVICES[address];state['services'].append(name)
        rcx,rdx,r8=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        if name=='find_quote':
            if rdx!=0x1489e4474:raise ValueError('Quote set')
            seq=readz(rcx);ret(rcx+seq.index(34)*2 if 34 in seq else 0)
        elif name=='copy':
            if r8:uc.mem_write(rcx,bytes(uc.mem_read(rdx,r8)))
            ret(rcx)
        elif name=='probe':
            if uc.reg_read(x.UC_X86_REG_RAX)!=0x2070:raise ValueError('Probe')
            ret(0x2070)
        elif name=='cookie':
            if rcx!=cookie:raise ValueError('Cookie')
            ret(uc.reg_read(x.UC_X86_REG_RAX))
        elif name=='allocate':
            if rdx!=0 or d(rcx+0x2008)!=state['input_units']+1 or d(rcx+0x200c)!=4096:raise ValueError('Buffer allocation ABI')
            uc.mem_write(rcx+0x2000,struct.pack('<Q',heap));uc.mem_write(rcx+0x200c,struct.pack('<i',state['input_units']+1));ret()
        elif name=='string_copy':
            values=readz(rdx);uc.mem_write(temp,packed(values+[0]));n=len(values)+1
            uc.mem_write(rcx,struct.pack('<Qii',temp,n,n));state['temporary']=rcx;ret(rcx)
        elif name=='string_move':
            if (rcx,rdx)!=(out,state['temporary']):raise ValueError('Move ABI')
            uc.mem_write(out,bytes(uc.mem_read(rdx,16)))
            if state['clear']:uc.mem_write(rdx,bytes(16))
            ret(out)
        else:
            if rcx not in (heap,temp):raise ValueError('Free pointer')
            state['frees'].append(rcx);ret()
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    regs=(x.UC_X86_REG_RBX,x.UC_X86_REG_RBP,x.UC_X86_REG_RSI,x.UC_X86_REG_RDI,x.UC_X86_REG_R12,x.UC_X86_REG_R13,x.UC_X86_REG_R14,x.UC_X86_REG_R15)
    def execute(text,flag,capacity,extra,wrapper,clear):
        source=units(text) if text is not None else [];source=source[:source.index(0)] if 0 in source else source
        state.clear();state.update(services=[],frees=[],core_calls=0,input_units=len(source),clear=clear)
        uc.mem_write(stack-0x4000,b'\x91'*0x4100);uc.mem_write(stack,struct.pack('<Q',stop))
        uc.mem_write(out-8,b'\x6a'*8+b'\x77'*512+b'\x6b'*8);uc.mem_write(endptr,struct.pack('<Q',0x12345678))
        if text is not None:uc.mem_write(inp,packed(units(text)+[0]))
        input_before=bytes(uc.mem_read(inp,len(packed(units(text)+[0])))) if text is not None else b''
        uc.reg_write(x.UC_X86_REG_RSP,stack)
        for i,r in enumerate(regs):uc.reg_write(r,100+i)
        for r,v in ((x.UC_X86_REG_RCX,inp if text is not None else 0),(x.UC_X86_REG_RDX,key),(x.UC_X86_REG_R8,out),
                (x.UC_X86_REG_R9,flag if wrapper else capacity)):uc.reg_write(r,v)
        uc.mem_write(stack+0x28,struct.pack('<Q',endptr if extra else 0) if wrapper else struct.pack('<Q',flag))
        if not wrapper:uc.mem_write(stack+0x30,struct.pack('<Q',endptr if extra else 0))
        uc.emu_start(0x14158edf0 if wrapper else 0x14158f1a0,stop,count=200000)
        if uc.reg_read(x.UC_X86_REG_RIP)!=stop or uc.reg_read(x.UC_X86_REG_RSP)!=stack+8:raise ValueError('Нет return')
        if [uc.reg_read(r) for r in regs]!=list(range(100,108)):raise ValueError('Nonvolatile')
        found,value,end=oracle(text,flag);success=found and bool(capacity) and (not wrapper or bool(source))
        if uc.reg_read(x.UC_X86_REG_RAX)&255!=int(success):raise ValueError('Result mismatch '+repr(text))
        if wrapper:
            if success:
                # Real downstream string primitive is not yet ported; fixture scans to NUL.
                visible=value[:value.index(0)] if 0 in value else value;n=len(visible)+1
                if bytes(uc.mem_read(out,16))!=struct.pack('<Qii',temp,n,n) or bytes(uc.mem_read(temp,n*2))!=packed(visible+[0]):raise ValueError('Wrapper output')
            elif bytes(uc.mem_read(out,16))!=b'\x77'*16:raise ValueError('Wrapper failure output')
            expected_frees=([temp] if success and not clear else [])+([heap] if len(source)+1>4096 else [])
            if state['frees']!=expected_frees:raise ValueError('Wrapper cleanup')
            if state['core_calls']!=int(bool(source)):raise ValueError('Native core dispatch')
        else:
            expected=packed(value[:capacity-1]+[0]) if success else (bytes(2) if capacity else b'')
            if expected and bytes(uc.mem_read(out,len(expected)))!=expected:raise ValueError('Core output')
            used=len(expected)
            if bytes(uc.mem_read(out+used,512-used))!=b'\x77'*(512-used):raise ValueError('Output tail')
        expected_end=inp+end*2 if success else (0 if capacity and not wrapper or wrapper and source else 0x12345678)
        if extra and q(endptr)!=expected_end:raise ValueError('End pointer')
        if bytes(uc.mem_read(out-8,8))!=b'\x6a'*8 or bytes(uc.mem_read(out+512,8))!=b'\x6b'*8:raise ValueError('Guards')
        if text is not None and bytes(uc.mem_read(inp,len(input_before)))!=input_before:raise ValueError('Input mutated')
        return dict(input_fixture=text if text is None or len(text)<256 else '<long-prefix>',input_kind='null' if text is None else 'utf16',input_units=len(source),flag=flag,capacity=capacity,
            extra=extra,move_clears_fixture=clear,success=success,result_utf16=value[:capacity-1] if success else [],
            end_units=end if success else None,core_calls=state['core_calls'],services=list(state['services']),complete_return=True)
    core=[execute(t,f,c,e,False,False) for t,f,c,e in itertools.product(TEXTS,(0,1),(0,1,2,7,64),(False,True))]
    whole=[]
    if wrapper_request is not None:
        for t,f,clear in itertools.product(TEXTS+(' '*4090+KEY+'x',' '*4091+KEY+'"long value"'),(0,1),(False,True)):
            count=len(units(t.split('\0')[0]))+1 if t is not None else 1
            whole.append(execute(t,f,count,True,True,clear))
    return dict(source_sha256=getter.SHA,fragments=fragments,literals=literals,ascii_table_sha256=getter.sha(table),core_cases=core,wrapper_cases=whole,
        limits=['Complete native core/ASCII compare and optional wrapper; quote search/byte copy and wrapper storage/string/probe/cookie remain fixtures.',
            'Fixed nonempty ASCII key; valid non-overlapping UTF16; capacity nonnegative; null key, negative capacity, errors/aliasing excluded.',
            'No actual command line, directory, file precedence or UI proof.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--request',type=Path,required=True);p.add_argument('--wrapper-request',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('Старый отчёт не перезаписывается')
    r=run(json.loads(a.request.read_text('utf-8')),json.loads(a.wrapper_request.read_text('utf-8')) if a.wrapper_request else None);r['replay_sha256']=getter.sha(Path(__file__).read_bytes())
    a.output.write_text(json.dumps(r,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(core=len(r['core_cases']),wrapper=len(r['wrapper_cases']))))
