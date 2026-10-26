"""Native config-number reader and comma replacement, real local Windows _wtoi."""
import ctypes
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def run():
    audit=load('audit-client-release'); path=HERE/'knowledge/native-contexts/quest-region-number-11316.json'
    context=json.loads(path.read_text('utf-8'))
    h=load('native-request-harness-11316').make_harness(context['exports'],{0x1445ceaa0,0x141435110})
    if not all(f.get('block_coverage_complete') for f in h.fragments): raise ValueError('Numeric read coverage incomplete')
    directory=ctypes.create_unicode_buffer(32768); kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    if not 0<kernel.GetSystemDirectoryW(directory,len(directory))<len(directory): raise ValueError('System directory unavailable')
    crt_path=Path(directory.value)/'ucrtbase.dll'; crt_hash=audit.sha256(crt_path); crt=ctypes.CDLL(str(crt_path))
    crt._wtoi.argtypes,crt._wtoi.restype=[ctypes.c_wchar_p],ctypes.c_int
    crt.setlocale.argtypes,crt.setlocale.restype=[ctypes.c_int,ctypes.c_char_p],ctypes.c_char_p
    locale=crt.setlocale(0,None)
    imported=load('build-object-zero-init-code').import_at(h.raw,h.image,0x14899bbb0)
    if (imported['dll'].lower(),imported['name'])!=('api-ms-win-crt-convert-l1-1-0.dll','_wtoi'):
        raise ValueError('Numeric region CRT import changed')
    uc,x,base=h.uc,h.x,h.scratch
    key,output,section,callback=base+0x1000,base+0x2000,base+0x3000,base+0x4000
    blocks={}; cursor=[base+0x10000]; current={}; calls=[]
    def reg(name): return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,value,size=8): uc.mem_write(at,(int(value)%(1 << (size*8))).to_bytes(size,'little'))
    def get(at,size=8): return int.from_bytes(uc.mem_read(at,size),'little')
    def wide(ptr):
        data=bytearray()
        for i in range(256):
            raw=bytes(uc.mem_read(ptr+i*2,2))
            if raw==b'\0\0': return data.decode('utf-16le')
            data+=raw
        raise ValueError('Config numeric text budget')
    def text(at): return wide(get(at)) if get(at+8,4) else ''
    def assign(at,value,empty_count=0):
        uc.mem_write(at,bytes(16))
        if value or empty_count:
            raw=value.encode('utf-16le')+b'\0\0'; ptr=cursor[0]+16; cursor[0]=ptr+((len(raw)+15)&~15)+16
            if cursor[0]>=base+0x30000: raise ValueError('Config text allocation budget')
            uc.mem_write(ptr-16,b'L'*16+raw+b'R'*16); blocks[ptr]=len(raw)
            put(at,ptr); put(at+8,len(raw)//2,4); put(at+12,len(raw)//2,4)
    def free_ptr(ptr):
        size=blocks.pop(ptr,None)
        if size is None or bytes(uc.mem_read(ptr-16,16))!=b'L'*16 or bytes(uc.mem_read(ptr+size,16))!=b'R'*16:
            raise ValueError('Numeric config temporary guards/free differ')
    def storage(machine):
        if reg('RCX')!=key or reg('R8')!=section or text(key)!='RegionSelect' or text(section)!='':
            raise ValueError('Lower config reader scope differs')
        calls.append('storage')
        if current['found']: assign(reg('RDX'),current['text'],current['empty_count'])
        h.finish(int(current['found']))
    def copy_string(machine):
        assign(reg('RCX'),text(reg('RDX')),current['empty_count']); h.finish(reg('RCX'))
    def append(machine):
        at,ptr,n=reg('RCX'),reg('RDX'),reg('R8')
        if n>256: raise ValueError('Native replacement append budget')
        addition=bytes(uc.mem_read(ptr,n*2)).decode('utf-16le')
        previous=text(at); old=get(at)
        assign(at,previous+addition)
        if old: free_ptr(old)
        calls.append('append'); h.finish(at)
    def compare_empty_suffix(machine):
        if reg('R8')!=0: raise ValueError('Only empty suffix compare expected for one-char comma pattern')
        h.finish(0)
    def crt_number(machine):
        ptr=reg('RCX')
        if ptr not in blocks and ptr!=0x1489e1b34: raise ValueError('CRT input outside current owned string/empty literal')
        value=wide(ptr); calls.append('wtoi:'+value)
        h.finish(crt._wtoi(value)&0xffffffff)
    def free(machine): free_ptr(reg('RCX')); h.finish()
    for address,handler in ((0x1445ceca0,storage),(0x1414266a0,copy_string),(0x141429e10,append),
            (0x14145f4a0,compare_empty_suffix),(0x141483080,free),(callback,crt_number)):
        h.add_fixture(address,handler)
    put(0x14899bbb0,callback)
    samples=[('',0),('0',0),('4',4),('7',7),('JP',0),('  +7x',7),('-1',-1),
        ('1,000',1000),('4,5',45),('1,2,3',123),(',4,',4),('0x10',0),('１２',12),('2147483647',2147483647)]
    cases=[]
    for empty_count in (0,1):
     for value,expected in samples:
      for found in (False,True):
        current.update(text=value,found=found,empty_count=empty_count); calls.clear(); blocks.clear(); cursor[0]=base+0x10000
        assign(key,'RegionSelect'); assign(section,''); uc.mem_write(output-16,b'A'*16+b'\x44\x33\x22\x11'+b'B'*16)
        inputs=[(at,bytes(uc.mem_read(at,n))) for at,n in ((key,16),(section,16))]
        uc.reg_write(x.UC_X86_REG_RDX,output); uc.reg_write(x.UC_X86_REG_R8,section)
        result=h.call(0x1445ceaa0,key)&255
        if result!=int(found) or get(output,4)!=(expected&0xffffffff if found else 0x11223344):
            raise ValueError('Config found/number differs '+repr((value,found,get(output,4),expected)))
        converted=[call[5:] for call in calls if call.startswith('wtoi:')]
        if converted!=([value.replace(',','')] if found else []): raise ValueError('Native comma removal differs')
        if any(bytes(uc.mem_read(at,len(raw)))!=raw for at,raw in inputs): raise ValueError('Config key/section changed')
        if bytes(uc.mem_read(output-16,16))!=b'A'*16 or bytes(uc.mem_read(output+4,16))!=b'B'*16:
            raise ValueError('Config result guards differ')
        free_ptr(get(key))
        if blocks: raise ValueError('Config numeric read leaked temporary strings')
        cases.append(dict(text=value,found=found,empty_count=empty_count,result=result,
            number=expected if found else None,converted=converted,calls=calls.copy()))
    if audit.sha256(crt_path)!=crt_hash or crt.setlocale(0,None)!=locale: raise ValueError('CRT changed')
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),exports=h.evidence,
        system_runtime=dict(path=str(crt_path),sha256=crt_hash,locale=locale.decode()),imported=imported,cases=cases,
        native_execution=True,network_used=False,active_region_verified=False,order_admitted=False,limits=context['limits'])
    target=audit.save_snapshot(h.root/'code-clues/quest-region-number-11316',report)
    return target,report


if __name__=='__main__':
    target,result=run(); print(json.dumps(dict(artifact=str(target),cases=len(result['cases'])),ensure_ascii=False))
