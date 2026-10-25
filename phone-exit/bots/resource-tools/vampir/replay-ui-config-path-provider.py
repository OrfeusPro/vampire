"""Complete native cached-path provider; TLS/initialization/storage/string services are fixtures."""
import argparse
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('path_wrapper', HERE / 'replay-ui-config-load-wrapper.py')
w = importlib.util.module_from_spec(spec); spec.loader.exec_module(w)
native, getter, unicorn, x = w.native, w.getter, w.unicorn, w.x
ROOT = 0x14144b5b0
OBJECT, GUARD, TLS_INDEX = 0x14b2bdcb8, 0x14b2bdcc8, 0x14b6a4c20
SERVICES = {0x1487e920c:'header', 0x141585780:'base_path', 0x141436ed0:'allocate',
    0x1487f5ab9:'copy', 0x1414324d0:'append', 0x1487e914c:'atexit', 0x1487e91a0:'footer'}


def run(request, join_request=None):
    if request['question'] != 'ui-nktileview-property-schema' or request['source_sha256'] != getter.SHA:
        raise ValueError('Другой вопрос / SHA')
    if hex(ROOT) not in {f['address'] for f in request['functions']}: raise ValueError('Нет explicit provider')
    if native.capstone.__version__ != '5.0.6' or unicorn.__version__ != '2.1.4': raise ValueError('Другие инструменты')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA: raise ValueError('Изменился EXE')
    image = native.Image(raw); row = image.containing(ROOT)
    if row is None or image.pe.base + image.roots[row][0] != ROOT: raise ValueError('Другой unwind root')
    selected = {image.roots[row]}
    if join_request is not None:
        if join_request['source_sha256'] != getter.SHA or join_request['question'] != request['question'] or '0x1414324d0' not in {f['address'] for f in join_request['functions']}:
            raise ValueError('Нет explicit join того же SHA')
        join_row = image.containing(0x1414324d0)
        if join_row is None or image.pe.base + image.roots[join_row][0] != 0x1414324d0: raise ValueError('Другой join root')
        selected.add(image.roots[join_row])
    fragments = native.decode_ranges(image, selected)
    rows = {r['address']:r for f in fragments for r in f['instructions']}
    literals = {}
    for address, text in ((0x1489e1b34,''), (0x1489f3fb0,'Config/')):
        off = image.offset(address-image.pe.base); encoded=(text+'\0').encode('utf-16le')
        if raw[off:off+len(encoded)] != encoded: raise ValueError('Другой literal')
        literals[text] = dict(address=hex(address), bytes=encoded.hex())
    atexit_target = rows[0x14144b617]['rip_references'][0]
    ranges = [(image.pe.base+f['begin_rva'],image.pe.base+f['end_rva']) for f in fragments]
    pages = {p for a,b in ranges for p in range(a&~4095,(b+4095)&~4095,4096)}
    pages.update(a&~4095 for f in fragments for r in f['instructions'] for a in r['rip_references'])
    pages.update(a&~4095 for a in SERVICES)
    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
    for page in pages:
        uc.mem_map(page,4096)
        try: off=image.offset(page-image.pe.base)
        except ValueError: continue
        uc.mem_write(page,raw[off:off+4096])
    scratch=0x20000000; uc.mem_map(scratch,0x120000)
    gs,tls_array,tls_block,source_object,source_data,storage,stack,stop=[scratch+a for a in
        (0,0x1000,0x2000,0x104000,0x105000,0x106000,0x110008,0x118000)]
    state={}
    services = dict(SERVICES)
    if join_request is not None: del services[0x1414324d0]
    def q(a): return struct.unpack('<Q',uc.mem_read(a,8))[0]
    def d(a): return struct.unpack('<i',uc.mem_read(a,4))[0]
    def ret(value=0):
        sp=uc.reg_read(x.UC_X86_REG_RSP); uc.reg_write(x.UC_X86_REG_RAX,value)
        uc.reg_write(x.UC_X86_REG_RIP,q(sp)); uc.reg_write(x.UC_X86_REG_RSP,sp+8)
    def hook(uc,address,size,_):
        if address==stop:return
        if address == 0x1414324d0 and join_request is not None:
            if [uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)] != [OBJECT,0x1489f3fb0,7]: raise ValueError('Native append entry ABI')
            state['calls'].append('append_native')
        if address not in services:
            if not any(a<=address and address+size<=b for a,b in ranges):raise ValueError('Вне provider '+hex(address))
            return
        name=services[address];state['calls'].append(name)
        rcx,rdx,r8=[uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        if name in ('header','footer'):
            if rcx!=GUARD: raise ValueError('Другой guard')
            uc.mem_write(GUARD,struct.pack('<i',-1 if name=='header' and state['initialize'] else 5));ret()
        elif name=='base_path':ret(source_object)
        elif name=='allocate':
            expected=state['count']+(8 if state['count'] else 9)
            if (rcx,rdx,r8)!=(OBJECT,expected,0):raise ValueError('Allocator ABI/count')
            uc.mem_write(OBJECT,struct.pack('<Q',storage));uc.mem_write(OBJECT+12,struct.pack('<i',expected));ret()
        elif name=='copy':
            if rdx == source_data:
                if (rcx,r8) != (storage,len(state['data'])):raise ValueError('Initial copy ABI')
            elif join_request is not None and rdx == 0x1489f3fb0:
                if rcx != storage + (d(OBJECT+8)-7)*2 or r8 != 14: raise ValueError('Native append copy ABI')
            else: raise ValueError('Другой copy source')
            uc.mem_write(rcx,bytes(uc.mem_read(rdx,r8)));ret(rcx)
        elif name=='append':
            if (rcx,rdx,r8)!=(OBJECT,0x1489f3fb0,7):raise ValueError('Append ABI')
            if d(OBJECT+8)!=state['count'] or q(OBJECT)!=storage:raise ValueError('До append count/data')
            if bytes(uc.mem_read(storage,len(state['data'])))!=state['data']:raise ValueError('Initial counted copy')
            # Explicit service fixture, not evidence for native append semantics.
            value=(state['prefix']+'Config/\0').encode('utf-16le')
            uc.mem_write(storage,value);uc.mem_write(OBJECT,struct.pack('<Qii',storage,len(value)//2,len(value)//2));ret(OBJECT)
        else:
            if rcx!=atexit_target:raise ValueError('Другой cleanup target')
            ret()
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    def execute(index,tls_epoch,epoch,count,initialize,prefix=''):
        data=(prefix+'\0').encode('utf-16le') if prefix else b''
        state.clear();state.update(calls=[],initialize=initialize,count=count,data=data,prefix=prefix)
        uc.mem_write(gs+0x58,struct.pack('<Q',tls_array));uc.mem_write(TLS_INDEX,struct.pack('<I',index))
        uc.mem_write(tls_array+index*8,struct.pack('<Q',tls_block));uc.mem_write(tls_block+0x101184,struct.pack('<i',tls_epoch))
        uc.mem_write(GUARD,struct.pack('<i',epoch));uc.mem_write(OBJECT,struct.pack('<Qii',storage,count,99))
        uc.mem_write(source_object,struct.pack('<Qii',source_data,count,count))
        uc.mem_write(storage,b'\x91'*256)
        if data:uc.mem_write(source_data,data)
        uc.mem_write(stack,struct.pack('<Q',stop));uc.reg_write(x.UC_X86_REG_RSP,stack)
        uc.reg_write(x.UC_X86_REG_GS_BASE,gs);uc.reg_write(x.UC_X86_REG_RBX,0x12345);uc.reg_write(x.UC_X86_REG_RDI,0x54321)
        uc.emu_start(ROOT,stop,count=512)
        if uc.reg_read(x.UC_X86_REG_RIP)!=stop or uc.reg_read(x.UC_X86_REG_RSP)!=stack+8:raise ValueError('Нет return')
        if (uc.reg_read(x.UC_X86_REG_RBX),uc.reg_read(x.UC_X86_REG_RDI))!=(0x12345,0x54321):raise ValueError('Nonvolatile registers')
        pointer=uc.reg_read(x.UC_X86_REG_RAX)
        if pointer!=(storage if initialize or count else 0x1489e1b34):raise ValueError('Неверный returned pointer')
        expected=['header','base_path','allocate']+(['copy'] if count else [])+['append','atexit','footer'] if initialize else (['header'] if epoch>tls_epoch else [])
        if initialize and join_request is not None:
            expected = ['header','base_path','allocate'] + (['copy'] if count else []) + ['append_native','copy','atexit','footer']
            prefix_result = prefix + ('' if not prefix or prefix.endswith(('/',chr(92))) else '/') + 'Config/'
            result_bytes = (prefix_result+'\0').encode('utf-16le')
            if d(OBJECT+8) != len(result_bytes)//2 or bytes(uc.mem_read(storage,len(result_bytes))) != result_bytes: raise ValueError('Неверный native provider+join result')
        if state['calls']!=expected:raise ValueError('Неверный service order')
        if not initialize and bytes(uc.mem_read(OBJECT,16))!=struct.pack('<Qii',storage,count,99):raise ValueError('Cache mutated')
        return dict(index=index,tls_epoch=tls_epoch,guard_epoch=epoch,count=count,initialize=initialize,
            prefix_fixture=prefix,services=list(state['calls']),returned_pointer=hex(pointer),complete_return=True)
    cached=[execute(1,t,e,c,False) for t,e,c in itertools.product((0,2),(-2,0,2),(0,1,8))]
    initial=[execute(i,t,t+1,len((p+'\0').encode('utf-16le'))//2 if p else 0,True,p)
        for i,t,p in itertools.product((0,2),(-2,0),(('', 'Demo/', 'Тест/', 'NoSeparator', 'Windows'+chr(92), '😀', 'A\0B') if join_request is not None else ('', 'Demo/', 'Тест/')))]
    return dict(source_sha256=getter.SHA,fragments=fragments,literals=literals,
        object=hex(OBJECT),guard=hex(GUARD),tls_index=hex(TLS_INDEX),atexit_target=hex(atexit_target),
        native_join=join_request is not None, cached_cases=cached,initial_cases=initial,
        limits=['Native provider with optional native join; GS/TLS memory, guard header/footer, base path, allocation/copy/atexit are fixtures; append fixture only without native_join.',
            'No actual base path, thread synchronization, mounted files, precedence or active UI proof.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--request',required=True,type=Path);p.add_argument('--join-request',type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    if a.output.exists():p.error('Старый отчёт не перезаписывается')
    result=run(json.loads(a.request.read_text('utf-8')),json.loads(a.join_request.read_text('utf-8')) if a.join_request else None);result['replay_sha256']=getter.sha(Path(__file__).read_bytes())
    a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(cached=len(result['cached_cases']),initial=len(result['initial_cases']))))
