"""Exact scalar wrappers, native decimal parser and actual local Windows CRT."""
import csv
import ctypes
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name, path=None):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'),path or HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install_runtime(h, read_input, callback_base=None):
    audit = load('audit-client-release')
    callback_base = h.scratch+0x7000 if callback_base is None else callback_base
    directory = ctypes.create_unicode_buffer(32768); kernel = ctypes.WinDLL('kernel32',use_last_error=True)
    if not 0<kernel.GetSystemDirectoryW(directory,len(directory))<len(directory): raise ValueError('System directory unavailable')
    crt_path = Path(directory.value)/'ucrtbase.dll'; crt_hash = audit.sha256(crt_path); crt = ctypes.CDLL(str(crt_path))
    crt.atoi.argtypes,crt.atoi.restype = [ctypes.c_char_p],ctypes.c_int
    crt._atoi64.argtypes,crt._atoi64.restype = [ctypes.c_char_p],ctypes.c_longlong
    crt.strtoul.argtypes,crt.strtoul.restype = [ctypes.c_char_p,ctypes.c_void_p,ctypes.c_int],ctypes.c_ulong
    crt.pow.argtypes,crt.pow.restype = [ctypes.c_double,ctypes.c_double],ctypes.c_double
    crt.setlocale.argtypes,crt.setlocale.restype = [ctypes.c_int,ctypes.c_char_p],ctypes.c_char_p
    locale = crt.setlocale(0,None)
    uc,x,base = h.uc,h.x,h.scratch
    imports = load('build-object-zero-init-code'); imported = []; calls = []

    def reg(name): return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,value,size=8): uc.mem_write(at,(int(value)%(1 << (size*8))).to_bytes(size,'little'))
    def f64(name): return struct.unpack('<d',(reg(name)&0xffffffffffffffff).to_bytes(8,'little'))[0]
    numeric_input = read_input
    def atoi(machine):
        calls.append('atoi'); h.finish(crt.atoi(numeric_input())&0xffffffff)
    def atoi64(machine):
        calls.append('_atoi64'); h.finish(crt._atoi64(numeric_input())&0xffffffffffffffff)
    def strtoul(machine):
        if reg('RDX') or reg('R8'): raise ValueError('Enum strtoul must use null endptr and base zero')
        calls.append('strtoul'); h.finish(crt.strtoul(numeric_input(),None,0))
    def power(machine):
        a,b = f64('XMM0'),f64('XMM1')
        if a!=10.0 or not 0<=b<=129: raise ValueError('Native decimal power arguments differ')
        calls.append('pow')
        result = crt.pow(a,b)
        uc.reg_write(x.UC_X86_REG_XMM0,int.from_bytes(struct.pack('<d',result),'little')); h.finish(reg('RAX'))
    for i,(slot,name,dll,callback) in enumerate((
            (0x14899bbf8,'atoi','api-ms-win-crt-convert-l1-1-0.dll',atoi),
            (0x14899bb78,'_atoi64','api-ms-win-crt-convert-l1-1-0.dll',atoi64),
            (0x14899bb98,'strtoul','api-ms-win-crt-convert-l1-1-0.dll',strtoul),
            (0x14899be00,'pow','api-ms-win-crt-math-l1-1-0.dll',power))):
        item = imports.import_at(h.raw,h.image,slot)
        if (item['dll'].lower(),item['name'])!=(dll,name): raise ValueError('Scalar import identity differs')
        imported.append(item); callback_at = callback_base+i*16
        h.add_fixture(callback_at,callback); put(slot,callback_at)
    def verify():
        if audit.sha256(crt_path)!=crt_hash or crt.setlocale(0,None)!=locale:
            raise ValueError('CRT changed during replay')
    return dict(calls=calls,imported=imported,system_runtime=dict(path=str(crt_path),sha256=crt_hash,locale=locale.decode()),verify=verify)


def run():
    audit = load('audit-client-release')
    path = HERE/'knowledge/native-contexts/quest-scalars-11316.json'
    context = json.loads(path.read_text('utf-8'))
    h = load('native-request-harness-11316').make_harness(context['exports'],{0x1445f5e60,0x1445f14f0},
            leaves={int(a,16):b for a,b in context['leaves'].items()})
    index_path = h.root/context['record_index']
    if audit.sha256(index_path)!=index_path.parent.name:
        raise ValueError('CSV index changed')
    index = json.loads(index_path.read_text('utf-8'))
    archive = Path(index['source']['path']); before = archive.stat()
    if index['source']['sha256']!=context['pak_sha256'] or audit.sha256(archive)!=context['pak_sha256']:
        raise ValueError('Current PAK changed')
    reader_path = HERE.parent/'rfnext/scan-pak.py'; reader = load('scalar_csv_reader',reader_path)
    if audit.sha256(reader_path)!=index['dependencies']['reader_sha256'] or audit.sha256(
            reader.ROOT/'tools/oodle-data-shared.dll')!=index['dependencies']['oodle_sha256']:
        raise ValueError('CSV decoder changed')
    entry = next(e for e in index['entries'] if e['entry']==context['csv_entry'])
    with archive.open('rb') as stream:
        header = reader.header(stream,entry['offset'],index['index_offset'])
        if header is None or header['end']!=entry['end']: raise ValueError('CSV entry changed')
        payload = reader.decode(stream,header)
    if hashlib.sha256(payload).hexdigest()!=context['csv_sha256']: raise ValueError('CSV changed')
    rows = list(csv.DictReader(io.StringIO(payload.decode('utf-8-sig'))))
    if len(rows)!=5944: raise ValueError('Current CSV row count changed')
    values = {}
    for row in rows:
        for column,kind in context['columns'].items():
            text = row[column]
            values[(kind,text)] = values.get((kind,text),0)+1

    uc,x,base = h.uc,h.x,h.scratch
    row,cells,heap = base+0x1000,base+0x2000,base+0x4000
    def reg(name): return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,value,size=8): uc.mem_write(at,(int(value)%(1 << (size*8))).to_bytes(size,'little'))
    def numeric_input():
        ptr = reg('RCX')
        if ptr not in (cells+32,heap): raise ValueError('CRT string pointer outside current cell')
        data = bytes(uc.mem_read(ptr,129)).split(b'\0',1)[0]
        if len(data)>128: raise ValueError('CRT string budget')
        return data
    runtime = install_runtime(h,numeric_input)
    calls = runtime['calls']
    functions = dict(u64=0x1445f5ed0,i32=0x1445f5eb0,boolean=0x1445f5e60,byte=0x1445f6040,f32=0x1445f5f10)
    results = []; mismatches = []; bounds = []

    def execute(kind,text,external):
        data = text.encode('ascii')
        if len(data)>128 or not external and len(data)>15: raise ValueError('Cell capacity budget')
        uc.mem_write(row,bytes(64)); uc.mem_write(cells-16,b'A'*16+bytes(96)+b'B'*16)
        uc.mem_write(heap-16,b'C'*16+bytes(256)+b'D'*16)
        cell = cells+32
        if external: put(cell,heap); put(cell+24,255); uc.mem_write(heap,data+b'\0')
        else: put(cell+24,15); uc.mem_write(cell,data+b'\0')
        put(cell+16,len(data)); put(row+0x20,3,4); put(row+0x28,cells)
        immutable = [(a,bytes(uc.mem_read(a,n))) for a,n in ((row,64),(cells-16,128),(heap-16,288))]
        calls.clear(); uc.reg_write(x.UC_X86_REG_RDX,1)
        result = h.call(functions[kind],row)
        if kind=='f32': result = reg('XMM0')&0xffffffff
        elif kind in ('byte','boolean'): result &=255
        elif kind=='i32': result &=0xffffffff
        if any(bytes(uc.mem_read(a,len(b)))!=b for a,b in immutable): raise ValueError('Scalar input/guards changed')
        return result,calls.copy()

    def expected(kind,text):
        if kind=='f32': return int.from_bytes(struct.pack('<f',float(text or '0')),'little')
        value = int(text or '0')
        if kind=='boolean': return int(value!=0)
        return value & (0xff if kind=='byte' else 0xffffffff if kind=='i32' else 0xffffffffffffffff)

    for (kind,text),occurrences in sorted(values.items()):
        for external in (False,True):
            if not external and len(text.encode())>15: continue
            result,used = execute(kind,text,external)
            want = expected(kind,text)
            if result!=want: mismatches.append(dict(kind=kind,text=text,external=external,expected=want,actual=result))
            results.append(dict(kind=kind,text=text,external=external,occurrences=occurrences,result=result,imports=used))
    lexical = []
    samples = [('boolean','true',0),('boolean','-1',1),('u64','-1',2**64-1),
               ('byte','08',0),('byte','010',8),('byte','0x10',16),('byte','256',0),
               ('f32','1e3',0),('f32','+1',0),('f32',' 1',0),('f32','1x',0),
               ('f32','.5',expected('f32','.5')),('f32','1.',expected('f32','1.')),
               ('f32','1.2.3',expected('f32','12.3'))]
    for kind,text,want in samples:
        for external in (False,True):
            result,used = execute(kind,text,external)
            if result!=want: raise ValueError('Lexical scalar differs '+kind+' '+text)
            lexical.append(dict(kind=kind,text=text,external=external,result=result,imports=used))
    # No valid source has zero columns. Test out-of-range indices against a nonempty row.
    for kind,address in functions.items():
        for column in (3,32767,0xffffffff):
            calls.clear(); uc.reg_write(x.UC_X86_REG_RDX,column)
            uc.reg_write(x.UC_X86_REG_XMM0,0xffffffffffffffff)
            result = h.call(address,row)
            value = reg('XMM0')&0xffffffff if kind=='f32' else result&(255 if kind in ('boolean','byte') else 0xffffffff if kind=='i32' else 2**64-1)
            if value or calls: raise ValueError('Scalar bounds called conversion')
            bounds.append(dict(kind=kind,column=column))
    runtime['verify']()
    after = archive.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns) or audit.sha256(archive)!=context['pak_sha256']:
        raise ValueError('PAK changed during replay')
    report = dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),
                  exports=h.evidence,imported=runtime['imported'],system_runtime=runtime['system_runtime'],
                  csv_sha256=context['csv_sha256'],source_rows=len(rows),source_values=sum(values.values()),source_cases=results,
                  source_mismatches=mismatches,lexical_cases=lexical,bounds=bounds,network_used=False,order_admitted=False,limits=context['limits'])
    target = audit.save_snapshot(h.root/'code-clues/quest-scalars-11316',report)
    return target,report


if __name__ == '__main__':
    target,result = run()
    print(json.dumps(dict(artifact=str(target),source_rows=result['source_rows'],cases=len(result['source_cases']),
                         mismatches=result['source_mismatches'][:8],lexical=len(result['lexical_cases']),bounds=len(result['bounds'])),ensure_ascii=False))
