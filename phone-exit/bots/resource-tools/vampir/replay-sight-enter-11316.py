"""Whole SightEnter with native callbacks/readers/copies/temporary destructors."""
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
    context_path=HERE/'knowledge/native-contexts/sight-enter-11316.json'
    context=json.loads(context_path.read_text('utf-8'));f={k:int(v,16) for k,v in context['functions'].items()}
    h=load('update-native-harness').make_harness(context,context['exports'],set(f.values()),leaves={int(k,16):v for k,v in context['leaves'].items()})
    uc,x=h.uc,h.x
    def require(ok,message):
        if not ok:raise ValueError(message)
    def reg(key):return uc.reg_read(getattr(x,'UC_X86_REG_'+key))
    def number(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,fmt,*values):uc.mem_write(at,struct.pack('<'+fmt,*values))
    packet,archive,buffer=h.scratch+0x30000,h.scratch+0x2000,h.scratch+0x5000
    state={};summary=dict(attempts=0,copies=0,temporary_records=0,destructors=0,released_buffers=0)
    def allocate(size):
        require(0<size<=8192 and state['heap']+size+64<h.scratch+0x28000,'SightEnter storage bound')
        at=state['heap']+16;state['heap']+=(size+63)&~15
        uc.mem_write(at-16,b'\xa5'*16+b'\x5a'*size+b'\xa6'*16);state['allocations'][at]=size;return at
    # Every receiver is registered from a native constructor/copy entry, including
    # actual stack temporaries and the destination slots in outer arrays.
    record_arrays={
        'character':((0x70,16),(0xc8,0x18),(0xe0,0x70),(0xf8,0x78)),
        'npc_create':((0x88,0x70),(0x110,16),(0x180,0x18),(0x1b0,16)),
        'gadget':((0x78,8),)}
    string_offsets={'character':(0x20,0x58,0x118,0x188,0x1a8),'npc_create':(0xf8,0x1f0),'gadget':(0xb0,)}
    map_offsets={'character':0x1d8,'npc_create':0x130}
    outer=((0x10,0x230,'character',0x145785200),(0x20,0x240,'npc_create',0x14579b810),
        (0x30,0x78,'ground',0x145791230),(0x40,0xd0,'gadget',0x1457911d0),
        (0x60,0x98,'circle',0x1457a38a0),(0x70,0x90,'tether',0x1457a44c0))
    def register(at,kind):
        require(h.scratch<=at<h.scratch+0x38000,'SightEnter object receiver outside scratch')
        state['owners'][at]=kind
        for offset,stride in record_arrays.get(kind,()):state['arrays'][at+offset]=stride
        state['strings'].update(at+offset for offset in string_offsets.get(kind,()))
        if kind in map_offsets:
            address=at+map_offsets[kind];state['maps'].add(address)
            state['generation']+=1;state['map_generation'][address]=state['generation']
    ctor_kinds={0x145783670:'character',0x14579a5a0:'npc_create',0x14578fe30:'gadget',
        0x14578fef0:'ground',0x1457a3480:'tether',0x1457a2590:'circle',0x1457841c0:'map_value'}
    copy_kinds={0x1456bedd0:'character',0x1456bfe20:'npc_create',0x1456bf7a0:'gadget'}
    destructors={row[3] for row in outer}
    def observe(machine,at,size,unused):
        if at in ctor_kinds:
            register(reg('RCX'),ctor_kinds[at]);summary['temporary_records']+=1
        if at in copy_kinds:
            register(reg('RCX'),copy_kinds[at]);summary['copies']+=1
        if at in destructors:summary['destructors']+=1
    import unicorn
    uc.hook_add(unicorn.UC_HOOK_CODE,observe)
    load('login-result-string-fixtures').install(load,h,context['string_storage'],state,lambda:reg('RCX'),(0,))
    old_assign=h.fixtures[0x1414277b0];old_free=h.fixtures[0x141483080]
    def assign(machine):
        require(reg('RCX') in state['strings'],'SightEnter FString receiver');old_assign(machine)
    def free(machine):
        at=reg('RCX');old_free(machine);uc.mem_write(at,b'\xdd'*state['allocations'][at])
    h.add_fixture(0x1414277b0,assign);h.add_fixture(0x141483080,free)
    def allocate_array(machine,reserve=False):
        at,count=(reg('RDX'),reg('R8')) if reserve else (reg('RCX'),reg('RDX'))
        require(at in state['arrays'] and count<=8,'SightEnter array receiver/count')
        put(at,'QII',allocate(count*state['arrays'][at]) if count else 0,0,count);h.finish()
    for at in (0x1456d2410,0x1456d2490,0x141685280,0x1419199a0,0x1419198a0,0x141539e70,0x14141ccf0,0x14141cb60):
        h.add_fixture(at,allocate_array)
    for at in (0x14578b170,0x1456ba3a0):h.add_fixture(at,lambda m:allocate_array(m,True))
    def copy_array(machine,stride):
        at,count=reg('RCX'),reg('RDX')
        require(state['arrays'].get(at)==stride and reg('R8')==0 and 0<count<=8 and number(at)==0,'SightEnter array copy owner')
        put(at,'QII',allocate(count*stride),count,count);h.finish()
    for at,stride in ((0x141436fe0,16),(0x141539310,0x18),(0x141afa010,0x70),(0x143767860,0x78),(0x14163cf80,8)):
        h.add_fixture(at,lambda machine,stride=stride:copy_array(machine,stride))
    def string_copy(machine):
        at,count=reg('RCX'),reg('RDX')
        require(at in state['strings'] and reg('R8')==0 and 0<count<=2048 and number(at)==0,'SightEnter string copy owner')
        put(at,'QII',allocate(count*2),count,count);h.finish()
    h.add_fixture(0x141436ed0,string_copy)
    def empty_clear(machine):
        require(reg('RCX')==0 and reg('RDX')==0,'SightEnter only fresh previous outer arrays supported');h.finish()
    for at in (0x1456bcae0,0x1456bcce0,0x1456bccb0,0x1456bcc70,0x1456bcd90,0x1456bcd20):h.add_fixture(at,empty_clear)
    def unexpected(machine):raise ValueError('SightEnter reserved storage/bitmap growth unsupported')
    for at in (0x14163d5c0,0x141437ee0,0x141539b80,0x141684cd0,0x141539920,0x141919430,0x1419192d0,0x1456d22b0,0x1456d2360,0x141433e10,0x141539850,0x14141c080):
        h.add_fixture(at,unexpected)
    # Sparse-map storage only; native insertion, field-copy, bitmap-copy and all
    # surrounding record destructors remain active.
    def init_map(machine):
        at=reg('RCX');require(at in state['maps'],'SightEnter map init owner')
        key=(at,state['map_generation'][at])
        if key not in state['map_storage']:state['map_storage'][key]=allocate(8*0x38)
        pointer=state['map_storage'][key];uc.mem_write(at,bytes(0x50));uc.mem_write(pointer,bytes(8*0x38))
        put(at,'QII',pointer,0,8);put(at+0x2c,'I',128);put(at+0x30,'ii',-1,0)
        put(at+0x38,'i',-1);put(at+0x48,'I',1);h.finish()
    def clear_map(machine):
        at,count=reg('RCX'),reg('RDX');require(at in state['maps'] and count<=8,'SightEnter map clear owner/count')
        if count:
            require(number(at)==0,'SightEnter map copy destination must be fresh')
            put(at,'QII',allocate(count*0x38),0,count)
        put(at+8,'I',0);put(at+0x28,'I',0);put(at+0x2c,'I',128);h.finish()
    def bit_append(machine):
        at=reg('RCX');require(at-0x10 in state['maps'] and reg('RDX')==0,'SightEnter bit append owner')
        count=number(at+0x18,4);require(count<8,'SightEnter inline bitmap bound');put(at+0x18,'I',count+1);h.finish()
    def predicate(machine):
        at,key=reg('RCX'),reg('RDX');require(at in state['maps'],'SightEnter map predicate owner')
        pointer,count=number(at),number(at+8,4);require(1<=count<=8 and not any(number(pointer+i*0x38,1)==key for i in range(count-1)),'SightEnter duplicate key reached insertion');h.finish()
    def map_value_clear(machine):
        require(state['owners'].get(reg('RCX'))=='map_value' or any(base+8<=reg('RCX')<base+length for base,length in state['allocations'].items()),'SightEnter map value cleanup owner');h.finish()
    h.add_fixture(0x14168a950,init_map);h.add_fixture(0x1456c7280,clear_map);h.add_fixture(0x141429680,bit_append)
    h.add_fixture(0x1456d4b20,predicate);h.add_fixture(0x145785b90,map_value_clear)
    h.add_fixture(0x1456d19c0,unexpected)
    old_utf16=h.fixtures[0x141436cc0]
    def bucket_allocate(machine):
        at=reg('RCX')
        if at-0x40 not in state['maps']:old_utf16(machine);return
        require(reg('RDX')==0 and reg('R9')==4 and reg('R8') in (2,4,8),'SightEnter buckets bound')
        put(at,'Q',allocate(reg('R8')*4));h.finish()
    h.add_fixture(0x141436cc0,bucket_allocate)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);directory=ctypes.create_unicode_buffer(32768)
    require(kernel.GetSystemDirectoryW(directory,len(directory))>0,'System runtime unavailable')
    dll_path=Path(directory.value)/'ucrtbase.dll';crt=ctypes.CDLL(str(dll_path));imports=load('build-object-zero-init-code')
    for row in context['crt_imports']:
        at=int(row['address'],16);off=h.image.offset(at-h.image.pe.base)
        require(h.raw[off:off+2]==b'\xff\x25','SightEnter math thunk differs')
        slot=at+6+struct.unpack_from('<i',h.raw,off+2)[0]
        require(imports.import_at(h.raw,h.image,slot)=={k:v for k,v in row.items() if k!='address'},'SightEnter math import differs')
        require(row['dll']=='api-ms-win-crt-math-l1-1-0.dll' and row['name'] in ('atan2','fmod'),'SightEnter math import unsupported')
        fn=getattr(crt,row['name']);fn.argtypes=[ctypes.c_double,ctypes.c_double];fn.restype=ctypes.c_double
        def math_call(machine,fn=fn):
            args=[struct.unpack('<d',(reg('XMM'+str(i))&((1<<64)-1)).to_bytes(8,'little'))[0] for i in (0,1)]
            uc.reg_write(x.UC_X86_REG_XMM0,int.from_bytes(struct.pack('<d',fn(*args)),'little'));h.finish()
        h.add_fixture(at,math_call)
    dispatch=0x1487e9660;off=h.image.offset(dispatch-h.image.pe.base)
    require(h.raw[off:off+2]==b'\x83\x3d' and dispatch+7+struct.unpack_from('<i',h.raw,off+2)[0]==0x14b271750,'SightEnter ISA branch differs');put(0x14b271750,'I',0)
    projection=load('sight-native-projection-11316')
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.sight_enter_event import decode_sight_enter
    def attempt(body):
        require(type(body) is bytes and len(body)<=8192,'SightEnter synthetic input bound')
        state.clear();state.update(heap=h.scratch+0x10000,allocations={},owners={},arrays={},strings=set(),maps=set(),generation=0,map_generation={},map_storage={})
        for offset,stride,kind,_ in outer:state['arrays'][packet+offset]=stride
        uc.mem_write(packet-16,b'\xa1'*16+bytes(0x88)+b'\xa2'*16)
        uc.mem_write(archive-16,b'\xa3'*16+bytes(0x40)+b'\xa4'*16)
        uc.mem_write(buffer-16,b'\xa7'*16+body+b'\xa8'*16)
        h.call(0x1456c0300,packet)
        uc.reg_write(x.UC_X86_REG_RDX,buffer);uc.reg_write(x.UC_X86_REG_R8,len(body));uc.reg_write(x.UC_X86_REG_R9,1)
        uc.mem_write(h.scratch+0x38028,bytes(8));h.call(0x144aacb40,archive)
        uc.reg_write(x.UC_X86_REG_RDX,archive)
        try:accepted=bool(h.call(0x1456c5390,packet,budget=5000000)&255)
        except Exception as exc:raise ValueError('SightEnter execution size='+str(len(body))+' rip='+hex(reg('RIP'))+' rcx='+hex(reg('RCX'))+' rdx='+hex(reg('RDX'))) from exc
        consumed=number(archive+0x30)-buffer;require(0<=consumed<=len(body),'SightEnter cursor exceeded input')
        if accepted:projection.compare(h,state,decode_sight_enter(body[:consumed],source_sha256=h.sha),packet,'sight')
        # Final-array iteration/free is a bounded owner harness, not a claim about
        # the game's complete packet destructor or engine/listener application.
        for offset,stride,kind,destroy in outer:
            pointer,count,capacity=struct.unpack('<QII',bytes(uc.mem_read(packet+offset,16)))
            require(0<=count<=capacity<=8 and (not pointer or pointer in state['allocations']),'SightEnter final array owner')
            for i in range(count):h.call(destroy,pointer+i*stride,budget=3000000)
            if pointer:h.call(0x141483080,pointer)
        require(set(state['allocations'])<=state.get('string_freed',set()),'SightEnter tracked buffers leaked')
        for at,length,a,b in ((packet,0x88,b'\xa1',b'\xa2'),(archive,0x40,b'\xa3',b'\xa4')):
            require(bytes(uc.mem_read(at-16,16))==a*16 and bytes(uc.mem_read(at+length,16))==b*16,'SightEnter frame guards')
        require(bytes(uc.mem_read(buffer-16,len(body)+32))==b'\xa7'*16+body+b'\xa8'*16,'SightEnter input changed')
        for at,length in state['allocations'].items():require(bytes(uc.mem_read(at-16,16))==b'\xa5'*16 and bytes(uc.mem_read(at+length,16))==b'\xa6'*16,'SightEnter heap guards')
        summary['attempts']+=1;summary['released_buffers']+=len(state['allocations'])
        return accepted,consumed
    fixtures=load('sight-enter-replay-fixtures-11316');bodies=fixtures.bodies();cases=[]
    for index,body in enumerate(bodies):
        sizes=range(len(body)+1) if index==len(bodies)-1 else [len(body)]
        for size in sizes:
            accepted,consumed=attempt(body[:size]);require(accepted==(size==len(body)),'SightEnter native prefix differs')
            try:decode_sight_enter(body[:size],source_sha256=h.sha);portable=True
            except ValueError:portable=False
            require(portable==accepted,'SightEnter portable prefix differs')
            cases.append(dict(index=index,size=size,accepted=accepted,consumed=consumed))
        accepted,consumed=attempt(body+b'\xff');require(accepted and consumed==len(body),'SightEnter trailing cursor differs')
    report=dict(source_sha256=h.sha,exports=h.evidence,context_sha256=hashlib.sha256(context_path.read_bytes()).hexdigest(),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=cases,summary=summary,network_used=False,
        crt_sha256=hashlib.sha256(dll_path.read_bytes()).hexdigest(),limits=[
            'Whole outer SightEnter reader and actual callbacks/temporary constructors/readers/copies/destructors; source SSE2/UCRT.',
            'Fresh owners and bounded allocation/string/map reset/free fixtures, <=8 slots, inline bitmap and <=3 wire map entries. Final-array cleanup iteration is harness-owned.',
            'No packet destructor/engine/actor/world/live integration proof; no reuse/OOM/real allocator/heap bitmap.'])
    path=load('audit-client-release').save_snapshot(h.root/'code-clues/sight-enter-whole-11316',report)
    return dict(report=str(path),cases=len(cases),summary=summary)


if __name__=='__main__':print(json.dumps(verify()))
