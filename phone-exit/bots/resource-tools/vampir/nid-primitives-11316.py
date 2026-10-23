"""Explicit current numeric/channel native dependencies and local Windows CRT."""
import ctypes
import hashlib
import importlib.util
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
EXPORT='run-37fa5992ea23'
EXPORT_SHA='2327d837934b6ea6f6709411b31d9746a46219b27cb7091e5bdf5cb4bb8966ab'
COMPARE=0x14145f1e0
COMPARE_SHA='591d6b9ae17a1ebc090ce3e9b853202de35bfecd86a36324752503d4548097c0'
CRT_LOCALE='LC_COLLATE=C;LC_CTYPE=Ukrainian_Ukraine.1251;LC_MONETARY=C;LC_NUMERIC=C;LC_TIME=C'
CHANNELS=dict(facebookKey=1,googleKey=5,gamecenterKey=6,twitterKey=12,mailUserKey=20,
    signinwithappleKey=26,googleIdKey=29,steamKey=30,epicKey=31,playstationKey=32,
    netmarbleKey=33,xboxKey=34,guest=100)


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def leaves(root):
    native=load('nid_primitive_source',HERE/'build-native-entry-code.py')
    source=Path(root)/'client-code-snapshots/d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960/ProjectRED-Win64-Shipping.exe'
    raw=source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=source.parent.name: raise ValueError('NID primitives source SHA changed')
    image=native.Image(raw); offset=image.offset(COMPARE-image.pe.base); data=raw[offset:offset+0x47]
    if hashlib.sha256(data).hexdigest()!=COMPARE_SHA: raise ValueError('NID channel compare SHA changed')
    return {COMPARE:data.hex()}


def install(h,events):
    native=load('nid_primitive_native',HERE/'build-native-entry-code.py')
    channel=next(f for f in h.fragments if int(f['address'],16)==0x144531900)
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64); decoder.detail=True
    targets=set()
    for row in channel['instructions']:
        ins=next(decoder.disasm(bytes.fromhex(row['bytes']),int(row['address'],16)))
        if ins.mnemonic=='mov' and ins.op_str.startswith('rdx, qword ptr [rip'):
            targets.update(ins.address+ins.size+op.mem.disp for op in ins.operands
                if op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP)
    if len(targets)!=13: raise ValueError('NID channel descriptor coverage changed')
    roots=set()
    for address,target in native.rip_candidates(h.image,targets):
        body=h.image.containing(address)
        if body and h.image.roots[body]==body and body[1]-body[0]<=64: roots.add(body)
    if not 1<=len(roots)<=16: raise ValueError('NID channel initializer budget')
    bindings=[]; arena=h.scratch+0x31000
    for fragment in native.decode_ranges(h.image,roots,functions=sorted(roots)):
        rows=fragment['instructions']
        if len(rows)!=7: continue
        literal,destination,call=rows[1:4]
        if (literal['mnemonic'],destination['mnemonic'],call['mnemonic'])!=('lea','lea','call'): continue
        if not literal['operands'].startswith('rdx,') or not destination['operands'].startswith('rcx,'): continue
        if len(literal['rip_references'])!=1 or len(destination['rip_references'])!=1: continue
        address=destination['rip_references'][0]
        if address not in targets: continue
        if call['direct_target']!=0x141426b30: raise ValueError('NID channel constructor differs')
        pointer=literal['rip_references'][0]; off=h.image.offset(pointer-h.image.pe.base); data=h.raw[off:off+256]
        end=next((n for n in range(0,256,2) if data[n:n+2]==bytes(2)),None)
        if end is None: raise ValueError('NID channel literal bound')
        value=data[:end].decode('utf-16le')
        if value.lower() not in {k.lower() for k in CHANNELS}: raise ValueError('NID channel literal differs')
        payload=data[:end+2]
        if arena+len(payload)>=h.scratch+0x32000: raise ValueError('NID channel permanent storage bound')
        h.uc.mem_write(arena,payload); h.uc.mem_write(address,struct.pack('<QII',arena,len(payload)//2,len(payload)//2))
        arena+=(len(payload)+15)&~15
        bindings.append(dict(global_address=hex(address),text=value,literal=hex(pointer),
            initializer=hex(fragment['root_begin_rva']+h.image.pe.base),instructions=rows))
    if len(bindings)!=13 or {int(b['global_address'],16) for b in bindings}!=targets:
        raise ValueError('NID channel initializer missing/ambiguous')

    workflow=load('nid_crt_paths',HERE/'research-workflow.py')
    crt_path,=workflow.system_runtime_files(['ucrtbase.dll'])
    crt_sha=hashlib.sha256(crt_path.read_bytes()).hexdigest()
    crt=ctypes.CDLL(str(crt_path))
    crt._wtoi.argtypes,crt._wtoi.restype=[ctypes.c_wchar_p],ctypes.c_int
    crt._finite.argtypes,crt._finite.restype=[ctypes.c_double],ctypes.c_int
    crt.iswspace.argtypes,crt.iswspace.restype=[ctypes.c_ushort],ctypes.c_int
    crt.setlocale.argtypes,crt.setlocale.restype=[ctypes.c_int,ctypes.c_char_p],ctypes.c_char_p
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetModuleFileNameW.argtypes=[ctypes.c_void_p,ctypes.c_wchar_p,ctypes.c_uint]
    buffer=ctypes.create_unicode_buffer(32768)
    if not kernel.GetModuleFileNameW(crt._handle,buffer,len(buffer)) or Path(buffer.value).resolve()!=crt_path:
        raise ValueError('Loaded CRT path differs from check dependency')
    locale=crt.setlocale(0,None)
    if not locale: raise ValueError('Cannot observe CRT locale')
    locale=locale.decode('ascii')
    if locale!=CRT_LOCALE: raise ValueError('NID primitives require reviewed local CRT locale')
    imports=load('nid_primitive_imports',HERE/'build-object-zero-init-code.py')
    numeric=next(f for f in h.fragments if int(f['address'],16)==0x1415e4460)
    imports_bound=[]

    def wtext(address):
        if not h.scratch<=address<h.scratch+0x40000: raise ValueError('NID CRT input outside scratch')
        data=bytearray()
        for n in range(512):
            if address+n*2+2>h.scratch+0x40000: raise ValueError('NID CRT string bound')
            unit=bytes(h.uc.mem_read(address+n*2,2))
            if unit==bytes(2): return data.decode('utf-16le')
            data.extend(unit)
        raise ValueError('NID CRT string budget')

    for row in numeric['instructions']:
        if not row['text'].startswith('CALL'): continue
        if len(row['references'])!=1: raise ValueError('NID numeric import reference differs')
        slot=int(row['references'][0],16); proof=imports.import_at(h.raw,h.image,slot)
        name=proof['name']
        expected={'_wtoi':'api-ms-win-crt-convert-l1-1-0.dll','_finite':'api-ms-win-crt-math-l1-1-0.dll',
            'iswspace':'api-ms-win-crt-string-l1-1-0.dll'}
        if name not in expected or proof['dll'].lower()!=expected[name]: raise ValueError('NID numeric import identity differs')
        target=h.scratch+0x3d000+len(imports_bound)*16
        h.uc.mem_write(slot,struct.pack('<Q',target))
        def fixture(machine,name=name):
            a=machine.reg_read(h.x.UC_X86_REG_RCX)
            if name=='_wtoi': result=crt._wtoi(wtext(a))
            elif name=='_finite':
                value=struct.unpack('<d',struct.pack('<Q',machine.reg_read(h.x.UC_X86_REG_XMM0)&((1<<64)-1)))[0]
                result=crt._finite(value)
            else: result=crt.iswspace(a&65535)
            events.append(dict(kind='local_CRT_call',name=name,result=result))
            h.finish(result&((1<<64)-1))
        h.add_fixture(target,fixture)
        imports_bound.append(dict(instruction=row['address'],**proof))
    if [i['name'] for i in imports_bound]!=['_wtoi','_finite','iswspace','iswspace']:
        raise ValueError('NID numeric imports coverage differs')
    def free(machine):
        pointer=machine.reg_read(h.x.UC_X86_REG_RCX)
        if pointer and not h.scratch<=pointer<h.scratch+0x40000: raise ValueError('NID primitive free bound')
        h.finish()
    h.add_fixture(0x141483080,free)
    def verify_crt():
        if hashlib.sha256(crt_path.read_bytes()).hexdigest()!=crt_sha or crt.setlocale(0,None).decode('ascii')!=locale:
            raise ValueError('NID CRT inputs changed during replay')
    return dict(bindings=bindings,imports=imports_bound,compare=dict(address=hex(COMPARE),bytes=0x47,sha256=COMPARE_SHA),
        crt=dict(path=str(crt_path),sha256=crt_sha,locale=locale)),verify_crt


def standalone(h,put,text,heap,events):
    numeric=[]; channels=[]
    descriptor,output=h.scratch+0x1e000,h.scratch+0x1e100
    numeric_values=('', '0','00','+0','-0',' 0','0 ','0.0','0abc','00abc','abc','abc0','+','-',
        '1','-1','200','1abc','0x10','0e9','0\tbad','0,1','0.1','2147483647','2147483648','-2147483649','\u00a00','\u20030')
    channel_values=[v for name in CHANNELS for v in (name,name.upper(),name.swapcase())]+['','unknown','email','mailUserKey ',' mailUserKey']
    for poison in (0,0x55,0xaa,0xff):
        for value in numeric_values:
            heap[0]=h.scratch+0x20000; events.clear(); put(descriptor,value)
            pointer=struct.unpack('<Q',bytes(h.uc.mem_read(descriptor,8)))[0]
            h.uc.mem_write(output-8,bytes([poison])*20); h.uc.reg_write(h.x.UC_X86_REG_RDX,pointer)
            result=h.call(0x1415e4460,receiver=output,budget=16384)
            if bytes(h.uc.mem_read(output-8,8))!=bytes([poison])*8 or bytes(h.uc.mem_read(output+4,8))!=bytes([poison])*8:
                raise ValueError('NID numeric canaries changed')
            numeric.append(dict(text=value,poison=poison,ok=bool(result&255),value=struct.unpack('<i',bytes(h.uc.mem_read(output,4)))[0],
                calls=events.copy(),canaries_unchanged=True))
        for value in channel_values:
            heap[0]=h.scratch+0x20000; events.clear(); put(descriptor,value)
            h.uc.mem_write(output-8,bytes([poison])*17); h.uc.reg_write(h.x.UC_X86_REG_RDX,descriptor)
            h.call(0x144531900,receiver=output,budget=16384)
            result=bytes(h.uc.mem_read(output,1))[0]
            if result!={k.lower():v for k,v in CHANNELS.items()}.get(value.lower(),0): raise ValueError('NID native channel mapping differs')
            if bytes(h.uc.mem_read(output-8,8))!=bytes([poison])*8 or bytes(h.uc.mem_read(output+1,8))!=bytes([poison])*8:
                raise ValueError('NID channel canaries changed')
            channels.append(dict(text=value,poison=poison,channel=result,canaries_unchanged=True))
    return dict(numeric=numeric,channels=channels)
