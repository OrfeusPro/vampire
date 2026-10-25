"""Native counted UTF16 path append; allocation and byte-copy are explicit fixtures."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('join_wrapper',HERE/'replay-ui-config-load-wrapper.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
native,getter,unicorn,x=w.native,w.getter,w.unicorn,w.x
ROOT=0x1414324d0
SERVICES={0x141438050:'reserve',0x141437970:'grow',0x1487f5ab9:'copy'}


def expected_text(prefix,suffix):
    if not suffix:
        return prefix+'/' if prefix and not prefix.endswith(('/',chr(92))) else prefix
    return prefix+('/' if prefix and not prefix.endswith(('/',chr(92))) and not suffix.startswith('/') else '')+suffix


def run(request):
    if request['question']!='ui-nktileview-property-schema' or request['source_sha256']!=getter.SHA:raise ValueError('Другой вопрос / SHA')
    if hex(ROOT) not in {f['address'] for f in request['functions']}:raise ValueError('Нет explicit join root')
    if native.capstone.__version__!='5.0.6' or unicorn.__version__!='2.1.4':raise ValueError('Другие инструменты')
    raw=Path(request['source']).read_bytes()
    if getter.sha(raw)!=getter.SHA:raise ValueError('Изменился EXE')
    image=native.Image(raw);row=image.containing(ROOT)
    if row is None or image.pe.base+image.roots[row][0]!=ROOT:raise ValueError('Другой unwind root')
    fragments=native.decode_ranges(image,{image.roots[row]})
    ranges=[(image.pe.base+f['begin_rva'],image.pe.base+f['end_rva']) for f in fragments]
    pages={p for a,b in ranges for p in range(a&~4095,(b+4095)&~4095,4096)}|{a&~4095 for a in SERVICES}
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page,4096);off=image.offset(page-image.pe.base);uc.mem_write(page,raw[off:off+4096])
    base=0x20000000;uc.mem_map(base,0x20000)
    obj,old,new,source,stack,stop=[base+a for a in (0x1000,0x2000,0x3000,0x4000,0x10008,0x1f000)]
    state={}
    def q(a):return struct.unpack('<Q',uc.mem_read(a,8))[0]
    def d(a):return struct.unpack('<i',uc.mem_read(a,4))[0]
    def ret(value=0):
        sp=uc.reg_read(x.UC_X86_REG_RSP);uc.reg_write(x.UC_X86_REG_RAX,value)
        uc.reg_write(x.UC_X86_REG_RIP,q(sp));uc.reg_write(x.UC_X86_REG_RSP,sp+8)
    def hook(uc,address,size,_):
        if address==stop:return
        if address not in SERVICES:
            if not any(a<=address and address+size<=b for a,b in ranges):raise ValueError('Вне join '+hex(address))
            return
        name=SERVICES[address];state['services'].append(name)
        rcx,rdx,r8=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        if name=='copy':
            count=state['suffix_units']
            if rdx!=source or r8!=count*2 or rcx!=q(obj)+(d(obj+8)-count)*2:raise ValueError('Copy ABI/count')
            uc.mem_write(rcx,bytes(uc.mem_read(rdx,r8)));ret(rcx)
        else:
            if rcx!=obj:raise ValueError('Другой object')
            capacity=d(obj+12);requested=rdx if name=='reserve' else d(obj+8)
            if requested<=capacity:raise ValueError('Лишняя allocation')
            if name=='grow' and rdx!=d(obj+8)-1:raise ValueError('Grow old count')
            ptr=q(obj);target=new if state['move'] else old
            data=bytes(uc.mem_read(ptr,capacity*2)) if ptr else b''
            if data:uc.mem_write(target,data)
            uc.mem_write(obj,struct.pack('<Q',target));uc.mem_write(obj+12,struct.pack('<i',requested));ret(target)
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    cases=[]
    for prefix,suffix,extra,move in itertools.product(('', 'A','A/','A'+chr(92),'/', 'Тест','A😀','A\0B'),
            ('','Config/','/Config/',chr(92)+'Config/','Тест','😀','A\0B'),(0,1,16),(False,True)):
        for empty_count in ((0,1) if not prefix else (None,)):
            count=empty_count if empty_count is not None else len(prefix.encode('utf-16le'))//2+1
            capacity=count+extra;data=(prefix+'\0').encode('utf-16le') if count else b''
            encoded=suffix.encode('utf-16le');state.clear();state.update(services=[],suffix_units=len(encoded)//2,move=move)
            for ptr in (old,new,source):uc.mem_write(ptr-8,b'\x6a'*8+b'\x91'*512+b'\x6b'*8)
            if data:uc.mem_write(old,data)
            if encoded:uc.mem_write(source,encoded)
            uc.mem_write(obj-8,b'\x6a'*8+struct.pack('<Qii',old if capacity else 0,count,capacity)+b'\x6b'*8)
            source_before=bytes(uc.mem_read(source-8,528))
            uc.mem_write(stack,struct.pack('<Q',stop));uc.reg_write(x.UC_X86_REG_RSP,stack)
            for reg,value in ((x.UC_X86_REG_RCX,obj),(x.UC_X86_REG_RDX,source if encoded else 0),(x.UC_X86_REG_R8,len(encoded)//2),
                    (x.UC_X86_REG_RBX,101),(x.UC_X86_REG_RBP,102),(x.UC_X86_REG_RSI,103),(x.UC_X86_REG_RDI,104)):uc.reg_write(reg,value)
            uc.emu_start(ROOT,stop,count=512)
            if uc.reg_read(x.UC_X86_REG_RIP)!=stop or uc.reg_read(x.UC_X86_REG_RSP)!=stack+8:raise ValueError('Нет return')
            if [uc.reg_read(r) for r in (x.UC_X86_REG_RBX,x.UC_X86_REG_RBP,x.UC_X86_REG_RSI,x.UC_X86_REG_RDI)]!=[101,102,103,104]:raise ValueError('Nonvolatile')
            expected=expected_text(prefix,suffix);output=(expected+'\0').encode('utf-16le') if expected or count else b''
            if d(obj+8)!=len(output)//2:raise ValueError('Неверный count')
            if output and bytes(uc.mem_read(q(obj),len(output)))!=output:raise ValueError('Неверный join')
            if d(obj+12)<d(obj+8):raise ValueError('Capacity')
            if bytes(uc.mem_read(source-8,528))!=source_before:raise ValueError('Source mutated')
            for ptr,size in ((obj,16),(old,512),(new,512)):
                if bytes(uc.mem_read(ptr-8,8))!=b'\x6a'*8 or bytes(uc.mem_read(ptr+size,8))!=b'\x6b'*8:raise ValueError('Guard')
            cases.append(dict(prefix=prefix,suffix=suffix,empty_count=empty_count,extra=extra,move_fixture=move,
                result=expected,count=d(obj+8),services=list(state['services']),complete_return=True))
    base_static = None
    if '0x141585780' in {f['address'] for f in request['functions']}:
        br = image.containing(0x141585780)
        if br is None or image.pe.base+image.roots[br][0] != 0x141585780: raise ValueError('Другой base root')
        bf = native.decode_ranges(image,{image.roots[br]})
        instructions={z['address']:z for f in bf for z in f['instructions']}
        if instructions[0x14158578d]['direct_target'] != 0x14157d1d0 or instructions[0x1415857be]['direct_target'] != 0x141585960 or instructions[0x1415857fb]['direct_target'] != 0x14158edf0:
            raise ValueError('Другие base callees')
        literals={}
        for a,t in ((0x148a12da0,'Saved'),(0x148a167c0,'-saveddirsuffix='),(0x148a16740,'_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'),(0x1489e5374,'_'),(0x1489f1520,'/')):
            off=image.offset(a-image.pe.base);encoded=(t+'\0').encode('utf-16le')
            if raw[off:off+len(encoded)]!=encoded:raise ValueError('Другой base literal')
            literals[t]=dict(address=hex(a),bytes=encoded.hex())
        base_static=dict(fragments=bf,literals=literals,cache_flag='manager+0x119',output_object='manager+0x48',
            method='static_instructions_only_not_executed',unknown=['Manager/base directory source, command line parser, sanitizing callees, active path and file precedence.'])
    return dict(source_sha256=getter.SHA,fragments=fragments,cases=cases,base_path_static=base_static,
        limits=['Complete native join; reserve/grow/copy fixtures, valid bounded non-overlapping counted UTF16 only.',
            'Embedded NUL is counted, no path canonicalization/OS filesystem/active config proof; overflow/error/aliasing excluded.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--request',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('Старый отчёт не перезаписывается')
    r=run(json.loads(a.request.read_text('utf-8')));r['replay_sha256']=getter.sha(Path(__file__).read_bytes())
    a.output.write_text(json.dumps(r,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(cases=len(r['cases']))))
