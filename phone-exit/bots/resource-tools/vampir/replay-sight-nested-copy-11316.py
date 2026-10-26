"""Native nested copies needed by outer SightEnter; fresh bounded memory owners."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def verify():
    path=HERE/'knowledge/native-contexts/sight-nested-copy-11316.json'
    context=json.loads(path.read_text('utf-8'));functions={k:int(v,16) for k,v in context['functions'].items()}
    h=load('update-native-harness').make_harness(context,context['exports'],set(functions.values()),
        leaves={int(k,16):v for k,v in context['leaves'].items()})
    uc,x=h.uc,h.x
    def require(ok,message):
        if not ok:raise ValueError(message)
    def number(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,fmt,*values):uc.mem_write(at,struct.pack('<'+fmt,*values))
    def reg(key):return uc.reg_read(getattr(x,'UC_X86_REG_'+key))
    source,target=h.scratch+0x1000,h.scratch+0x2000
    state={};cases=[]
    def allocate(size):
        require(0<size<=4096 and state['heap']+size+64<h.scratch+0x30000,'Nested copy allocation bound')
        at=state['heap']+16;state['heap']+=(size+63)&~15
        uc.mem_write(at-16,b'\xa1'*16+b'\x5a'*size+b'\xa2'*16);state['allocations'][at]=size;return at
    def reset(size):
        state.clear();state.update(heap=h.scratch+0x10000,allocations={})
        for at in (source,target):uc.mem_write(at-16,b'\xb1'*16+bytes(size)+b'\xb2'*16)
    def guard(size):
        for at in (source,target):
            require(bytes(uc.mem_read(at-16,16))==b'\xb1'*16 and bytes(uc.mem_read(at+size,16))==b'\xb2'*16,'Nested copy object guard')
        for at,length in state['allocations'].items():
            require(bytes(uc.mem_read(at-16,16))==b'\xa1'*16 and bytes(uc.mem_read(at+length,16))==b'\xa2'*16,'Nested copy heap guard')
    def vector_allocate(machine,stride,offset):
        at,count=reg('RCX'),reg('RDX')
        require(at==target+offset and reg('R8')==0 and 0<count<=(2048 if stride==2 else 8) and number(at)==0,'Nested copy allocation receiver')
        put(at,'QII',allocate(count*stride),count,count);h.finish()
    h.add_fixture(0x141436ed0,lambda m:vector_allocate(m,2,state['string_offset']))
    h.add_fixture(0x141436fe0,lambda m:vector_allocate(m,16,0x30))
    def map_allocate(machine):
        require(reg('RCX')==target and 0<=reg('RDX')<=8 and number(target)==0,'Fresh map storage receiver')
        count=reg('RDX');put(target,'QII',allocate(count*0x38) if count else 0,0,count);h.finish()
    h.add_fixture(0x141539df0,map_allocate)
    def bucket_allocate(machine):
        require(reg('RCX')==target+0x40 and reg('RDX')==0 and reg('R9')==4 and reg('R8') in (2,4,8),'Fresh map bucket allocation receiver')
        put(target+0x40,'Q',allocate(reg('R8')*4));h.finish()
    h.add_fixture(0x141436cc0,bucket_allocate)
    def unexpected(machine):raise ValueError('Nested copy reserved storage exceeded')
    for at in (0x141539850,0x141433e10,0x145785b90,0x14142e6f0):h.add_fixture(at,unexpected)
    def call(name,count=None):
        uc.reg_write(x.UC_X86_REG_RDX,source)
        if count is not None:uc.reg_write(x.UC_X86_REG_R8,count)
        return h.call(functions[name],target,budget=100000)
    def make_string(at,text):
        raw=text.encode('utf-16le')+b'\0\0' if text else b''
        pointer=allocate(len(raw)) if raw else 0
        if raw:uc.mem_write(pointer,raw)
        put(at,'QII',pointer,len(raw)//2,len(raw)//2);return pointer,raw
    def assert_independent_string(offset,pointer,raw):
        actual=number(target+offset)
        require(number(target+offset+8,4)==len(raw)//2,'Copied string count')
        if raw:
            require(actual in state['allocations'] and actual!=pointer and bytes(uc.mem_read(actual,len(raw)))==raw,'Copied string aliases or differs')
            uc.mem_write(pointer,b'\xdd'*len(raw));require(bytes(uc.mem_read(actual,len(raw)))==raw,'Copied string changed with source')
        else:require(actual==0,'Empty copied string pointer')
    for kind,size,offset in [('string',16,0),('appearance',0x40,0x18),('guild',0x60,0x10)]:
        for text in ('','Игрок 🦇','x'*31):
            for count in ((0,1,2,8) if kind=='appearance' else (0,)):
                reset(size);state['string_offset']=offset;uc.mem_write(source,bytes((i*37+19)%256 for i in range(size)))
                pointer,raw=make_string(source+offset,text)
                if kind=='appearance':
                    data=bytes((i*17+3)%256 for i in range(count*16));items=allocate(len(data)) if data else 0
                    if data:uc.mem_write(items,data)
                    put(source+0x30,'QII',items,count,count)
                before=bytes(uc.mem_read(source,size));call(kind)
                require(bytes(uc.mem_read(source,size))==before,'Copy changed source object')
                assert_independent_string(offset,pointer,raw)
                if kind=='appearance':
                    require(number(target)==0x149920090 and bytes(uc.mem_read(target+8,10))==before[8:18] and bytes(uc.mem_read(target+0x28,2))==before[0x28:0x2a],'Appearance scalar copy')
                    dst=number(target+0x30);require(number(target+0x38,4)==count,'Appearance count copy')
                    for i in range(count):
                        require(dst!=items and number(dst+i*16)==0x149920048,'Appearance item owner/table')
                        for off,length in ((8,4),(12,1),(14,2)):
                            require(bytes(uc.mem_read(dst+i*16+off,length))==data[i*16+off:i*16+off+length],'Appearance item fields')
                    if data:
                        saved=bytes(uc.mem_read(dst,len(data)));uc.mem_write(items,b'\xdd'*len(data));require(bytes(uc.mem_read(dst,len(data)))==saved,'Appearance aliases source')
                elif kind=='guild':
                    require(number(target)==0x149920598,'Guild table')
                    for off,length in ((8,8),(0x20,4),(0x30,8),(0x38,8),(0x40,1),(0x50,8),(0x58,1)):
                        require(bytes(uc.mem_read(target+off,length))==before[off:off+length],'Guild fields')
                guard(size);cases.append(dict(kind=kind,text_units=len(raw)//2,count=count))
    for count in (0,1,2,8):
        size=max(1,count)*0x78;reset(size);data=bytes((i*13+7)%256 for i in range(size));uc.mem_write(source,data)
        call('actions',count)
        for i in range(count):
            for off,length in ((8,1),(12,4),(16,8),(24,8),(40,1),(56,24),(88,1),(96,24)):
                require(bytes(uc.mem_read(target+i*0x78+off,length))==data[i*0x78+off:i*0x78+off+length],'ActorAction copy fields')
            require(number(target+i*0x78)==0x149921ad8,'ActorAction table')
        saved=bytes(uc.mem_read(target,size));uc.mem_write(source,b'\xdd'*size);require(bytes(uc.mem_read(target,size))==saved,'ActorAction copy aliases')
        guard(size);cases.append(dict(kind='actions',count=count))
    for count in (0,1,2,8):
        for buckets in (0,1,2,4,8):
            for holes in (False,True):
                reset(0x50);put(target+0x2c,'I',128)
                data=bytes((i*11+3)%256 for i in range(count*0x38));pointer=allocate(len(data)) if data else 0
                if data:uc.mem_write(pointer,data)
                put(source,'QII',pointer,count,count)
                mask=sum(1<<i for i in range(count) if not holes or i%2==0)
                put(source+0x10,'I',mask);put(source+0x28,'IIII',count,128,0xffffffff,0)
                heads=struct.pack('<'+'i'*buckets,*range(buckets)) if buckets else b''
                bucket_pointer=allocate(len(heads)) if buckets>1 else 0
                if bucket_pointer:uc.mem_write(bucket_pointer,heads)
                elif buckets:put(source+0x38,'i',0)
                put(source+0x40,'QI',bucket_pointer,buckets)
                before=bytes(uc.mem_read(source,0x50));call('map')
                require(bytes(uc.mem_read(source,0x50))==before,'Map copy changed source')
                require(number(target+8,4)==count and number(target+0x48,4)==buckets and number(target+0x10,4)==mask and number(target+0x28,4)==count,'Map counts/bitmap copy')
                dst=number(target)
                for i in range(count):
                    require(dst!=pointer,'Map aliases nodes')
                    fields=((0,1),(16,1),(20,4),(24,4),(28,4),(40,8),(48,4),(52,4)) if mask&(1<<i) else ((0,8),)
                    for off,length in fields:require(bytes(uc.mem_read(dst+i*0x38+off,length))==data[i*0x38+off:i*0x38+off+length],'Map node fields')
                if count:
                    saved=bytes(uc.mem_read(dst,len(data)));uc.mem_write(pointer,b'\xdd'*len(data));require(bytes(uc.mem_read(dst,len(data)))==saved,'Map nodes alias source')
                if buckets:
                    dest_heads=number(target+0x40) or target+0x38
                    require(bytes(uc.mem_read(dest_heads,len(heads)))==heads and (not bucket_pointer or dest_heads!=bucket_pointer),'Map bucket ownership/values')
                    if bucket_pointer:
                        uc.mem_write(bucket_pointer,b'\xdd'*len(heads));require(bytes(uc.mem_read(dest_heads,len(heads)))==heads,'Map buckets alias source')
                guard(0x50);cases.append(dict(kind='map',count=count,buckets=buckets,holes=holes))
    report=dict(source_sha256=h.sha,exports=h.evidence,context_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=cases,network_used=False,
        limits=['Native FString/appearance/Guild/ActorAction/map copies and fresh map reset/bitmap copy; synthetic memory, no wire parsing.',
            'Bounded fresh storage <=8 items, inline bitmap <=8 bits; heap bitmap, reuse, source cleanup/free and whole outer SightEnter not proved.'])
    saved=load('audit-client-release').save_snapshot(h.root/'code-clues/sight-nested-copy-11316',report)
    return dict(report=str(saved),cases=len(cases))


if __name__=='__main__':print(json.dumps(verify()))
