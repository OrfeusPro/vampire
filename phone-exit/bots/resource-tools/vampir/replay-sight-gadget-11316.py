"""Whole Gadget with native key vector, optional ActorOwner, strings, XYZ and yaw."""
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
    context_path=HERE/'knowledge/native-contexts/sight-gadget-11316.json'
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
    from vampir_core.sight_gadget_record import decode_gadget
    packet,archive,buffer,storage=[h.scratch+n for n in (0x1000,0x2000,0x5000,0x10000)]
    state={}
    load('login-result-string-fixtures').install(load,h,context['string_storage'],state,packet,(0xb0,))
    def allocate(machine):
        count=reg('RDX');require(reg('RCX')==packet+0x78 and count<=128,'Gadget key storage fixture bound')
        uc.mem_write(packet+0x78,struct.pack('<QII',storage if count else 0,0,count));h.finish()
    def no_growth(machine):raise ValueError('Reserved Gadget key storage exceeded')
    h.add_fixture(0x14141cb60,allocate);h.add_fixture(0x14141c080,no_growth)
    for table,reader in [(0x1499218e0,f['reader']),(0x1499218b8,f['optional_wrapper']),(0x149921840,f['owner_reader'])]:
        require(struct.unpack_from('<Q',h.raw,h.image.offset(table+0x20-h.image.pe.base))[0]==reader,'Gadget virtual reader differs')
    require(struct.unpack_from('<3Q',h.raw,h.image.offset(0x149924c90-h.image.pe.base))==(0x141b0aa50,0x1456d2030,f['keys_callback']),'Gadget keys descriptor differs')
    def text(at):
        pointer,count,capacity=struct.unpack('<QII',bytes(uc.mem_read(at,16)))
        require(0<=count==capacity<=2048,'Gadget FString descriptor differs')
        if not count:return ''
        require(pointer in state['allocations'] and state['allocations'][pointer]>=count*2,'Gadget FString owner differs')
        data=bytes(uc.mem_read(pointer,count*2));require(data[-2:]==b'\0\0','Gadget FString terminator differs')
        return data[:-2].decode('utf-16le')
    def attempt(body):
        state.clear();state.update(heap=h.scratch+0x18000,allocations={},body=body)
        uc.mem_write(packet-16,b'\xa1'*16+bytes(0xd0)+b'\xa2'*16)
        uc.mem_write(archive-16,b'\xa3'*16+bytes(0x40)+b'\xa4'*16)
        uc.mem_write(buffer-16,b'\xa7'*16+body+b'\xa8'*16)
        uc.mem_write(storage-16,b'\xa9'*16+b'\x5a'*(128*8)+b'\xaa'*16)
        h.call(f['constructor'],packet)
        require(number(packet,8)==0x1499218e0 and number(packet+0x88,8)==0x1499218b8 and number(packet+0x98,8)==0x149921840,'Gadget constructors differ')
        uc.reg_write(x.UC_X86_REG_RDX,buffer);uc.reg_write(x.UC_X86_REG_R8,len(body));uc.reg_write(x.UC_X86_REG_R9,1)
        uc.mem_write(h.scratch+0x38028,bytes(8));h.call(f['input_constructor'],archive)
        uc.reg_write(x.UC_X86_REG_RDX,archive)
        accepted=bool(h.call(f['reader'],packet,budget=3000000)&255)
        consumed=number(archive+0x30,8)-buffer;require(0<=consumed<=len(body),'Gadget cursor exceeded input')
        for at,size,a,b in [(packet,0xd0,b'\xa1',b'\xa2'),(archive,0x40,b'\xa3',b'\xa4'),(storage,128*8,b'\xa9',b'\xaa')]:
            require(bytes(uc.mem_read(at-16,16))==a*16 and bytes(uc.mem_read(at+size,16))==b*16,'Gadget frame/storage guard differs')
        require(bytes(uc.mem_read(buffer-16,len(body)+32))==b'\xa7'*16+body+b'\xa8'*16,'Gadget input changed')
        for at,size in state['allocations'].items():require(bytes(uc.mem_read(at-16,16))==b'\xa5'*16 and bytes(uc.mem_read(at+size,16))==b'\xa6'*16,'Gadget string guard differs')
        if accepted:
            value=decode_gadget(body[:consumed],source_sha256=h.sha)
            for offset,width in [(8,8),(0x10,4),(0x14,4),(0x18,4),(0x60,1),(0x61,1),(0x68,8),(0x70,4),(0x74,1),(0xc8,1)]:
                require(number(packet+offset,width)==value.at(offset),'Gadget scalar differs')
            expected=struct.unpack('<fff',struct.pack('<III',*value.at(0x20).bits));actual=struct.unpack('<ddd',bytes(uc.mem_read(packet+0x20,24)))
            for a,b in zip(actual,expected):require(math.isnan(a) if math.isnan(b) else struct.pack('<d',a)==struct.pack('<d',b),'Gadget XYZ differs')
            keys=value.at(0x78);pointer=number(packet+0x78,8);require(number(packet+0x80,4)==len(keys) and (not keys or pointer==storage),'Gadget keys count/owner differs')
            require(tuple(number(pointer+i*8,8) for i in range(len(keys)))==keys,'Gadget keys differ')
            owner=value.at(0x88);require(bool(number(packet+0x90,1))==(owner is not None),'Gadget owner presence differs')
            if owner is not None:
                for offset,width in [(8,1),(0x10,8),(0x28,8)]:require(number(packet+0x98+offset,width)==owner.at(offset),'Gadget owner scalar differs')
                require(text(packet+0xb0)==owner.at(0x18),'Gadget owner name differs')
        return accepted,consumed
    def body_for(style,count,present,yaw,enum):
        key=[0,2**63,2**64-1][style];other=key^0xffffffffffffffff
        bits=[(0,0x80000000,0x3f800000),(0x7fc12345,0x7f800000,0xff800000),(0x7f7fffff,0xc2f68000,0x3f000000)][style]
        keys=[(0,2**63,2**64-1)[i%3] for i in range(count)];label=['','Владелец 🦇','x'*31][style].encode('utf-8')
        body=(struct.pack('<QIII',key,1,0x80000000,0xffffffff)+struct.pack('<IIIBBBQIBH',*bits,yaw,(0,1,255)[style],enum,other,0x12345678,enum,count)
            +b''.join(struct.pack('<Q',v) for v in keys)+bytes([present]))
        if present:body+=bytes([enum])+struct.pack('<QH',other,len(label))+label+struct.pack('<Q',key)
        body+=bytes([(enum+17)%256]);require(decode_gadget(body,source_sha256=h.sha).at(0x38).raw_byte==yaw,'Gadget raw yaw differs')
        return body
    cases=[]
    bodies=[(style,count,present,body_for(style,count,present,(0,127,255)[style],255)) for style in range(3) for count in (0,1,3,8,64,128) for present in (0,255)]
    bodies.extend((i%3,2,255,body_for(i%3,2,255,i,i)) for i in range(256))
    for index,(style,count,present,body) in enumerate(bodies):
        sizes=range(len(body)+1) if index<36 and count<=3 else sorted({0,1,32,48,49,50,len(body)//2,len(body)-1,len(body)}) if index<36 else [len(body)]
        for size in sizes:
            accepted,consumed=attempt(body[:size]);require(accepted==(size==len(body)),'Gadget native prefix differs')
            try:decode_gadget(body[:size],source_sha256=h.sha);portable=True
            except ValueError:portable=False
            require(portable==accepted,'Gadget portable prefix differs')
            cases.append(dict(index=index,style=style,count=count,present=present,size=size,accepted=accepted,consumed=consumed))
        accepted,consumed=attempt(body+b'\xff');require(accepted and consumed==len(body),'Gadget trailing cursor differs')
    report=dict(source_sha256=h.sha,exports=h.evidence,context_sha256=hashlib.sha256(context_path.read_bytes()).hexdigest(),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=cases,network_used=False,
        crt_sha256=hashlib.sha256(dll_path.read_bytes()).hexdigest(),
        limits=['Whole Gadget constructor/reader with actual input, keys vector/resize/callback and optional ActorOwner/string reader.',
            'Fresh empty owners; bounded preallocation up to 128 keys and string allocation/free fixtures; reuse/growth/allocator not proved.',
            'Source SSE2 yaw and real UCRT math; raw heading separate. Valid UTF8 fixtures only. No outer SightEnter/actor/world/live claim.'])
    path=load('audit-client-release').save_snapshot(h.root/'code-clues/sight-gadget-11316',report)
    return dict(report=str(path),cases=len(cases))


if __name__=='__main__':print(json.dumps(verify()))
