"""Native CSV cell/SSO wrappers + actual Windows atoi + zero service gate."""
import ctypes
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    audit=load('audit-client-release');path=HERE/'knowledge/native-contexts/quest-empty-group-11316.json'
    context=json.loads(path.read_text('utf-8'))
    h=load('native-request-harness-11316').make_harness(context['exports'],{int(a,16) for a in context['functions']},
        leaves={int(a,16):b for a,b in context['leaves'].items()})
    slot=int(context['import_slot'],16)
    imported=load('build-object-zero-init-code').import_at(h.raw,h.image,slot)
    if (imported['dll'].lower(),imported['name'])!=(context['import_dll'],context['import_name']):raise ValueError('CSV CRT import changed')
    directory=ctypes.create_unicode_buffer(32768);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    if not 0<kernel.GetSystemDirectoryW(directory,len(directory))<len(directory):raise ValueError('System directory unavailable')
    crt_path=Path(directory.value)/'ucrtbase.dll';crt_hash=audit.sha256(crt_path);crt=ctypes.CDLL(str(crt_path))
    crt.atoi.argtypes=[ctypes.c_char_p];crt.atoi.restype=ctypes.c_int
    crt.setlocale.argtypes=[ctypes.c_int,ctypes.c_char_p];crt.setlocale.restype=ctypes.c_char_p
    locale=crt.setlocale(0,None)
    uc,x,base=h.uc,h.x,h.scratch;row,cells,heap,gate=tuple(base+n for n in (0x1000,0x2000,0x4000,0x6000))
    callback=base+0x7000;calls=[]
    def put(at,n,size=8):uc.mem_write(at,int(n).to_bytes(size,'little',signed=n<0))
    def atoi(machine):
        at=uc.reg_read(x.UC_X86_REG_RCX)
        if not (cells<=at<cells+96 or heap<=at<heap+256):raise ValueError('CRT pointer outside explicit cell buffers')
        raw=bytes(uc.mem_read(at,256)).split(b'\0',1)[0]
        if len(raw)>128:raise ValueError('CRT input exceeds test budget')
        value=crt.atoi(raw);calls.append(dict(text=raw.decode('ascii'),value=value));h.finish(value&0xffffffff)
    h.add_fixture(callback,atoi);put(slot,callback)
    cases=[]
    for text,expected in [('',0),('0',0),('  ',0),('000',0),('10000',10000),('-1',-1),('  +17x',17)]:
      for external in (False,True):
        uc.mem_write(row,bytes(64));uc.mem_write(cells-16,b'A'*16+bytes(96)+b'B'*16);uc.mem_write(heap-16,b'C'*16+bytes(256)+b'D'*16)
        raw=text.encode()+b'\0';cell=cells+32
        if external:put(cell,heap);uc.mem_write(heap,raw);put(cell+24,127)
        else:uc.mem_write(cell,raw);put(cell+24,15)
        put(cell+16,len(text));put(row+0x20,3,4);put(row+0x28,cells)
        immutable=[(a,bytes(uc.mem_read(a,n))) for a,n in ((row,64),(cells-16,128),(heap-16,288))]
        calls.clear();uc.reg_write(x.UC_X86_REG_RDX,1)
        result=h.call(0x1445f5eb0,row)&0xffffffff
        if result!=expected&0xffffffff or len(calls)!=1 or calls[0]['text']!=text:raise ValueError('CSV/CRT conversion differs')
        integrated=False
        if expected==0:
            calls.clear();put(gate+8,1,2);uc.reg_write(x.UC_X86_REG_RDX,row)
            if h.call(0x145a4d2f0,gate)&255 or len(calls)!=1:raise ValueError('Zero group gate differs')
            integrated=True
        if any(bytes(uc.mem_read(a,len(b)))!=b for a,b in immutable):raise ValueError('CSV cell/input guards changed')
        cases.append(dict(text=text,external=external,value=expected,zero_gate_integrated=integrated))
    # Missing/out-of-range columns must not dereference cell storage or call CRT.
    bounds=[]
    for column in (3,32767,0xffffffff):
        calls.clear();uc.reg_write(x.UC_X86_REG_RDX,column)
        if h.call(0x1445f5eb0,row)&0xffffffff or calls:raise ValueError('Column bounds differ')
        bounds.append(column)
    if audit.sha256(crt_path)!=crt_hash or crt.setlocale(0,None)!=locale:raise ValueError('CRT changed during replay')
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),exports=h.evidence,
        imported=imported,system_runtime=dict(path=str(crt_path),sha256=crt_hash,locale=locale.decode()),cases=cases,column_bounds=bounds,
        native_execution=True,network_used=False,order_admitted=False,limits=context['limits'])
    target=audit.save_snapshot(h.root/'code-clues/quest-empty-group-11316',report);return target,report


if __name__=='__main__':
    target,result=run();print(json.dumps(dict(artifact=str(target),cases=len(result['cases']),bounds=len(result['column_bounds'])),ensure_ascii=False))
