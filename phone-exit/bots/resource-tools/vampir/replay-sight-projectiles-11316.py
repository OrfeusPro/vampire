"""Whole optional projectile array: native wrapper/vector/callback/records and input."""
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
    context_path=HERE/'knowledge/native-contexts/sight-projectiles-11316.json'
    context=json.loads(context_path.read_text('utf-8'));f={k:int(v,16) for k,v in context['functions'].items()}
    h=load('update-native-harness').make_harness(context,context['exports'],set(f.values()),
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
    from vampir_core.sight_projectile_records import decode_optional_projectile_circles,decode_projectile_circle_data
    from vampir_core.character_select_result import SelectionRecord,WireVector3,WireHeading
    packet,archive,buffer,storage=[h.scratch+n for n in (0x1000,0x2000,0x5000,0x10000)]
    def allocate(machine):
        count=reg('RDX');require(reg('RCX')==packet+0x60 and count<=64,'Projectile storage fixture bound')
        uc.mem_write(packet+0x60,struct.pack('<QII',storage if count else 0,0,count));h.finish()
    def clear(machine):
        require(reg('RCX')==0 and reg('RDX')==0,'Only empty previous projectile storage supported');h.finish()
    def no_growth(machine):raise ValueError('Reserved projectile storage exceeded')
    h.add_fixture(0x141539e70,allocate);h.add_fixture(0x1456bcd20,clear);h.add_fixture(0x141539920,no_growth)
    for table,expected in [(0x149924f00,(0x141b0aa50,f['resize'],f['callback']))]:
        require(struct.unpack_from('<3Q',h.raw,h.image.offset(table-h.image.pe.base))==expected,'Projectile descriptor differs')
    for table,reader in [(0x149922468,f['reader']),(0x149922390,f['circle_reader']),(0x149922348,f['record_reader'])]:
        require(struct.unpack_from('<Q',h.raw,h.image.offset(table+0x20-h.image.pe.base))[0]==reader,'Projectile virtual reader differs')
    def compare(record,at):
        for offset,value in record.fields:
            if isinstance(value,SelectionRecord):compare(value,at+offset)
            elif isinstance(value,WireVector3):
                expected=struct.unpack('<fff',struct.pack('<III',*value.bits));actual=struct.unpack('<ddd',bytes(uc.mem_read(at+offset,24)))
                for a,b in zip(actual,expected):require(math.isnan(a) if math.isnan(b) else struct.pack('<d',a)==struct.pack('<d',b),'Projectile XYZ differs')
            elif not isinstance(value,WireHeading):
                width=2 if offset in (8,0x38) else 8 if offset in (0x18,0x68) else 4
                require(number(at+offset,width)==value,'Projectile scalar differs')
    def attempt(body):
        uc.mem_write(packet-16,b'\xa1'*16+bytes(0x88)+b'\xa2'*16)
        uc.mem_write(archive-16,b'\xa3'*16+bytes(0x40)+b'\xa4'*16)
        uc.mem_write(buffer-16,b'\xa5'*16+body+b'\xa6'*16)
        uc.mem_write(storage-16,b'\xa7'*16+b'\x5a'*(64*0x98)+b'\xa8'*16)
        h.call(0x1456c0300,packet)
        require(number(packet,8)==0x149922490 and number(packet+0x50,8)==0x149922468,'SightEnter optional constructor differs')
        uc.reg_write(x.UC_X86_REG_RDX,buffer);uc.reg_write(x.UC_X86_REG_R8,len(body));uc.reg_write(x.UC_X86_REG_R9,1)
        uc.mem_write(h.scratch+0x38028,bytes(8));h.call(f['input_constructor'],archive)
        uc.reg_write(x.UC_X86_REG_RDX,archive)
        accepted=bool(h.call(f['reader'],packet+0x50,budget=3000000)&255)
        consumed=number(archive+0x30,8)-buffer;require(0<=consumed<=len(body),'Projectile cursor exceeded input')
        for at,size,a,b in [(packet,0x88,b'\xa1',b'\xa2'),(archive,0x40,b'\xa3',b'\xa4'),(storage,64*0x98,b'\xa7',b'\xa8')]:
            require(bytes(uc.mem_read(at-16,16))==a*16 and bytes(uc.mem_read(at+size,16))==b*16,'Projectile frame/storage guards changed')
        require(bytes(uc.mem_read(buffer-16,len(body)+32))==b'\xa5'*16+body+b'\xa6'*16,'Projectile input changed')
        if accepted:
            records=decode_optional_projectile_circles(body[:consumed],source_sha256=h.sha)
            require(bool(number(packet+0x58,1))==(records is not None),'Projectile optional presence differs')
            if records is not None:
                count=number(packet+0x68,4);require(count==len(records),'Projectile count differs')
                pointer=number(packet+0x60,8);require(not count or pointer==storage,'Projectile storage owner differs')
                for i,record in enumerate(records):
                    at=pointer+i*0x98
                    require(number(at,8)==0x149922390 and number(at+8,8)==0x149922348,'Projectile copied vtables differ')
                    compare(record,at)
        return accepted,consumed
    def record_for(i,yaw):
        key=[0,2**63,2**64-1][i%3];bits=[(0,0x80000000,0x3f800000),(0x7fc12345,0x7f800000,0xff800000),(0x7f7fffff,0xc2f68000,0x3f000000)][i%3]
        body=struct.pack('<HIIIQIIIHBQIIIII',0xffff,0xffffffff,2,3,key,*bits,0x8000,yaw,key,0xffffffff,bits[0],*reversed(bits))
        require(decode_projectile_circle_data(body,source_sha256=h.sha).at(8).at(0x40).raw_byte==yaw,'Projectile raw heading differs')
        return body
    cases=[]
    bodies=[b'\0']+[bytes([present])+struct.pack('<H',count)+b''.join(record_for(i,i%256) for i in range(count))
        for present in (1,255) for count in (0,1,2,8,64)]
    bodies.extend(b'\xff\1\0'+record_for(yaw%3,yaw) for yaw in range(256))
    for index,body in enumerate(bodies):
        count=struct.unpack_from('<H',body,1)[0] if body[0] else 0
        sizes=range(len(body)+1) if index<11 and count<=8 else [0,1,2,3,len(body)//2,len(body)-1,len(body)] if index<11 else [len(body)]
        for size in sorted(set(sizes)):
            accepted,consumed=attempt(body[:size]);require(accepted==(size==len(body)),'Projectile native prefix differs')
            try:decode_optional_projectile_circles(body[:size],source_sha256=h.sha);portable=True
            except ValueError:portable=False
            require(portable==accepted,'Projectile portable prefix differs')
            cases.append(dict(index=index,count=count,size=size,accepted=accepted,consumed=consumed))
        accepted,consumed=attempt(body+b'\xff');require(accepted and consumed==len(body),'Projectile trailing cursor differs')
    report=dict(source_sha256=h.sha,exports=h.evidence,context_sha256=hashlib.sha256(context_path.read_bytes()).hexdigest(),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=cases,network_used=False,
        crt_sha256=hashlib.sha256(dll_path.read_bytes()).hexdigest(),
        limits=['Whole optional wrapper, vector/resize/callback, constructors/readers/cleanup with actual input and XYZ/yaw math.',
            'Only empty previous storage and preallocated capacity up to 64 records; growth/reuse and outer SightEnter/actor semantics not proved.',
            'Source SSE2 yaw branch with real UCRT math; raw heading preserved separately. Portable exact-size policy is stricter than native.'])
    path=load('audit-client-release').save_snapshot(h.root/'code-clues/sight-projectiles-11316',report)
    return dict(report=str(path),cases=len(cases))


if __name__=='__main__':print(json.dumps(verify()))
