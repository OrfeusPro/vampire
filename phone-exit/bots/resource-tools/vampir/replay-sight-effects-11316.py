"""Whole ground/tether readers and constructors with real input, XYZ and yaw math."""
import ctypes
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def verify():
    context_path=HERE/'knowledge/native-contexts/sight-effects-11316.json'
    context=json.loads(context_path.read_text('utf-8'));f={k:int(v,16) for k,v in context['functions'].items()}
    h=load('native-request-harness-11316').make_harness(context['exports'],set(f.values()),
        leaves={int(k,16):v for k,v in context['leaves'].items()})
    uc,x=h.uc,h.x
    def require(ok,message):
        if not ok:raise ValueError(message)
    def reg(key):return uc.reg_read(getattr(x,'UC_X86_REG_'+key))
    def number(at,width):return int.from_bytes(uc.mem_read(at,width),'little')
    # Execute the same source's SSE2 yaw path and the actual local UCRT math imports.
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);directory=ctypes.create_unicode_buffer(32768)
    require(kernel.GetSystemDirectoryW(directory,len(directory))>0,'System runtime directory unavailable')
    dll_path=Path(directory.value)/'ucrtbase.dll';crt=ctypes.CDLL(str(dll_path))
    imports=load('build-object-zero-init-code')
    for row in context['crt_imports']:
        at=int(row['address'],16);off=h.image.offset(at-h.image.pe.base)
        require(h.raw[off:off+2]==b'\xff\x25','Sight math thunk differs')
        slot=at+6+struct.unpack_from('<i',h.raw,off+2)[0];actual=imports.import_at(h.raw,h.image,slot)
        require(actual=={k:v for k,v in row.items() if k!='address'} and actual['dll']=='api-ms-win-crt-math-l1-1-0.dll'
            and actual['name'] in ('atan2','fmod'),'Sight math import differs')
        fn=getattr(crt,actual['name']);fn.argtypes=[ctypes.c_double,ctypes.c_double];fn.restype=ctypes.c_double
        def math_call(machine,fn=fn):
            a,b=[struct.unpack('<d',(reg('XMM'+str(i))&((1<<64)-1)).to_bytes(8,'little'))[0] for i in (0,1)]
            uc.reg_write(x.UC_X86_REG_XMM0,int.from_bytes(struct.pack('<d',fn(a,b)),'little'));h.finish()
        h.add_fixture(at,math_call)
    dispatch=0x1487e9660
    require(h.raw[h.image.offset(dispatch-h.image.pe.base):h.image.offset(dispatch-h.image.pe.base)+2]==b'\x83\x3d','Sight ISA shape differs')
    isa=dispatch+7+struct.unpack_from('<i',h.raw,h.image.offset(dispatch-h.image.pe.base)+2)[0]
    require(isa==0x14b271750,'Sight ISA variable differs');uc.mem_write(isa,bytes(4))
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.sight_effect_records import decode_ground_effect_data,decode_tether_effect_data
    packet,archive,buffer=[h.scratch+n for n in (0x1000,0x2000,0x5000)]
    cases=[]
    for kind,decoder,size,table in [('ground',decode_ground_effect_data,0x78,0x1499223d8),('tether',decode_tether_effect_data,0x90,0x149922420)]:
        require(struct.unpack_from('<Q',h.raw,h.image.offset(table+0x20-h.image.pe.base))[0]==f[kind+'_reader'],'Sight reader binding differs')
        def attempt(body):
            uc.mem_write(packet-16,b'\xa1'*16+bytes(size)+b'\xa2'*16)
            uc.mem_write(archive-16,b'\xa3'*16+bytes(0x40)+b'\xa4'*16)
            uc.mem_write(buffer-16,b'\xa5'*16+body+b'\xa6'*16)
            h.call(f[kind+'_constructor'],packet);require(number(packet,8)==table,'Sight effect constructor differs')
            uc.reg_write(x.UC_X86_REG_RDX,buffer);uc.reg_write(x.UC_X86_REG_R8,len(body));uc.reg_write(x.UC_X86_REG_R9,1)
            uc.mem_write(h.scratch+0x38028,bytes(8));h.call(f['input_constructor'],archive)
            uc.reg_write(x.UC_X86_REG_RDX,archive)
            accepted=bool(h.call(f[kind+'_reader'],packet,budget=300000)&255)
            consumed=number(archive+0x30,8)-buffer;require(0<=consumed<=len(body),'Sight effect cursor exceeded input')
            for at,length,a,b in [(packet,size,b'\xa1',b'\xa2'),(archive,0x40,b'\xa3',b'\xa4')]:
                require(bytes(uc.mem_read(at-16,16))==a*16 and bytes(uc.mem_read(at+length,16))==b*16,'Sight effect frame guard differs')
            require(bytes(uc.mem_read(buffer-16,len(body)+32))==b'\xa5'*16+body+b'\xa6'*16,'Sight effect input changed')
            if accepted:
                result=decoder(body[:consumed],source_sha256=h.sha)
                vectors=(0x28,) if kind=='ground' else (0x30,0x48)
                heading=0x40 if kind=='ground' else 0x60
                for offset,value in result.fields:
                    if offset in vectors:
                        expected=struct.unpack('<fff',struct.pack('<III',*value.bits));actual=struct.unpack('<ddd',bytes(uc.mem_read(packet+offset,24)))
                        for a,b in zip(actual,expected):require(math.isnan(a) if math.isnan(b) else struct.pack('<d',a)==struct.pack('<d',b),'Sight XYZ widening differs')
                    elif offset!=heading:
                        width=1 if offset in (0x70,0x8c) else 8 if offset in (8,0x20,0x28) else 4
                        require(number(packet+offset,width)==value,'Sight effect scalar differs')
            return accepted,consumed
        for style in range(3):
            key=(0,2**63,2**64-1)[style];bits=[(0,0x80000000,0x3f800000),(0x7f800000,0xff800000,0x7fc12345),(0xc2f68000,0x3f000000,0x7f7fffff)][style]
            for yaw in range(256):
                prefix=struct.pack('<QIIIQ',key,0xffffffff,2,3,key)
                if kind=='ground':body=prefix+struct.pack('<IIIBIIB',*bits,yaw,0xffffffff,bits[0],(0,3,255)[style])
                else:body=prefix+struct.pack('<QIIIIIIBIB',key,*bits,*reversed(bits),yaw,0xffffffff,(0,1,255)[style])
                require(decoder(body,source_sha256=h.sha).at(0x40 if kind=='ground' else 0x60).raw_byte==yaw,'Sight raw heading differs')
                sizes=range(len(body)+1) if yaw in (0,127,255) else [len(body)]
                for length in sizes:
                    accepted,consumed=attempt(body[:length]);require(accepted==(length==len(body)),'Sight effect native prefix differs')
                    try:decoder(body[:length],source_sha256=h.sha);portable=True
                    except ValueError:portable=False
                    require(portable==accepted,'Sight effect portable prefix differs')
                    cases.append(dict(kind=kind,style=style,yaw=yaw,size=length,accepted=accepted,consumed=consumed))
                accepted,consumed=attempt(body+b'\xff');require(accepted and consumed==len(body),'Sight effect trailing cursor differs')
    report=dict(source_sha256=h.sha,exports=h.evidence,context_sha256=hashlib.sha256(context_path.read_bytes()).hexdigest(),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=cases,network_used=False,
        crt_sha256=hashlib.sha256(dll_path.read_bytes()).hexdigest(),
        limits=['Whole two record readers/constructors with input and XYZ/yaw math, source SSE2 branch; no outer SightEnter/callback/actor proof.',
            'Raw heading byte is preserved separately from native canonical yaw; portable exact-size policy rejects trailing bytes.'])
    path=load('audit-client-release').save_snapshot(h.root/'code-clues/sight-effects-11316',report)
    return dict(report=str(path),cases=len(cases))


if __name__=='__main__':print(json.dumps(verify()))
