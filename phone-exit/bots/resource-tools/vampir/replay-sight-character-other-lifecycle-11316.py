"""Native read/copy/destroy of fresh CharacterOther with bounded storage/free."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
LIMITS=['Whole CharacterOther reader, copy and native source/final destructors; accepted and truncated synthetic bodies.',
    'Fresh owners, at most 8 array/map slots, bounded allocation/free/storage fixtures. Map clear/reset stays a storage fixture; no real allocator/OOM/heap bitmap/reuse proof.',
    'No outer SightEnter callback, actor/world/live/multi-account proof. Source SSE2 yaw and real UCRT imports only.']


def install(h,context,source,state,compare):
    uc,x=h.uc,h.x;target=h.scratch+0x32000;source_map=source+0x1d8;target_map=target+0x1d8
    summary=dict(attempts=0,copies=0,destructors=0,released_owner_buffers=0)
    def require(ok,message):
        if not ok:raise ValueError(message)
    def reg(key):return uc.reg_read(getattr(x,'UC_X86_REG_'+key))
    def number(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,fmt,*values):uc.mem_write(at,struct.pack('<'+fmt,*values))
    def allocate(size):
        require(0<size<=8192 and state['heap']+size+64<h.scratch+0x30000,'Lifecycle allocation bound')
        at=state['heap']+16;state['heap']+=(size+63)&~15
        uc.mem_write(at-16,b'\xa5'*16+b'\x5a'*size+b'\xa6'*16);state['allocations'][at]=size;return at
    # Preserve the proven string fixture's ownership/double-free checks, then poison
    # the released buffer so an alias cannot accidentally pass comparison.
    old_free=h.fixtures[0x141483080]
    def release(machine):
        pointer=reg('RCX');old_free(machine);uc.mem_write(pointer,b'\xdd'*state['allocations'][pointer])
    h.add_fixture(0x141483080,release)
    def reserve(machine,offset,stride,maximum=8):
        at,count=reg('RCX'),reg('RDX')
        require(at==target+offset and reg('R8')==0 and 0<count<=maximum and number(at)==0,'Lifecycle copy allocation receiver')
        put(at,'QII',allocate(count*stride),count,count);h.finish()
    def string_reserve(machine):
        offset=reg('RCX')-target;require(offset in (0x20,0x58,0x118,0x188,0x1a8),'Lifecycle string copy owner')
        reserve(machine,offset,2,2048)
    h.add_fixture(0x141436ed0,string_reserve)
    for at,offset,stride in ((0x141436fe0,0x70,16),(0x141539310,0xc8,0x18),(0x141afa010,0xe0,0x70),(0x143767860,0xf8,0x78)):
        h.add_fixture(at,lambda machine,offset=offset,stride=stride:reserve(machine,offset,stride))
    old_clear=h.fixtures[0x1456c7280]
    def map_clear(machine):
        at,count=reg('RCX'),reg('RDX')
        require(at in (source_map,target_map) and 0<=count<=8,'Lifecycle map clear receiver/count')
        if state.get('phase')=='destroy':
            require(count==0,'Lifecycle destructor map count');put(at+8,'I',0);put(at+0x28,'I',0);h.finish();return
        if at==source_map:old_clear(machine);return
        require(number(at)==0,'Lifecycle map copy fresh owner')
        put(at,'QII',allocate(count*0x38) if count else 0,0,count)
        uc.mem_write(at+0x10,bytes(0x20));put(at+0x2c,'I',128);h.finish()
    h.add_fixture(0x1456c7280,map_clear)
    def bit_append(machine):
        at=reg('RCX');require(at==source_map+0x10 and reg('RDX')==0,'Lifecycle bitmap append owner')
        count=number(at+0x18,4);require(count<8,'Lifecycle bitmap bound');put(at+0x18,'I',count+1);h.finish()
    h.add_fixture(0x141429680,bit_append)
    # The same address is the existing UTF16 scratch allocator during input.
    old_utf16=h.fixtures[0x141436cc0]
    def buckets(machine):
        if reg('RCX')!=target_map+0x40:old_utf16(machine);return
        require(reg('RDX')==0 and reg('R9')==4 and reg('R8') in (2,4,8),'Lifecycle hash bucket bound')
        put(target_map+0x40,'Q',allocate(reg('R8')*4));h.finish()
    h.add_fixture(0x141436cc0,buckets)
    def bitmap_grow(machine):raise ValueError('Lifecycle heap bitmap/reuse not supported')
    h.add_fixture(0x141433e10,bitmap_grow)
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.sight_character_other import decode_character_other
    def live_allocations():return set(state['allocations'])-state.get('string_freed',set())
    def destroy(at):
        state['phase']='destroy';h.call(int(context['functions']['destroy'],16),at,budget=3000000)
        require(number(at)==0x14991ee40,'Lifecycle destructor final table')
    def operation(accepted,body):
        summary['attempts']+=1
        source_owned=live_allocations();uc.mem_write(target-16,b'\xc1'*16+bytes(0x230)+b'\xc2'*16)
        if accepted:
            state['phase']='copy';uc.reg_write(x.UC_X86_REG_RDX,source)
            require(h.call(int(context['functions']['copy'],16),target,budget=3000000)==target,'Lifecycle copy return')
            summary['copies']+=1
            value=decode_character_other(body,source_sha256=h.sha);compare(value,target,'root')
            for offset in (0x20,0x58,0x70,0xc8,0xe0,0xf8,0x118,0x188,0x1a8,0x1d8,0x218):
                original=number(source+offset)
                if original in source_owned and number(source+offset+8,4)>0:
                    copied=number(target+offset)
                    require(copied in live_allocations()-source_owned,'Lifecycle copied pointer aliases source')
        destroy(source)
        summary['destructors']+=1
        require(source_owned<=state.get('string_freed',set()),'Lifecycle source buffers leaked')
        if accepted:
            compare(value,target,'root');destroy(target);summary['destructors']+=1
        require(not live_allocations(),'Lifecycle buffers leaked after destructors')
        summary['released_owner_buffers']+=len(state['allocations'])
        require(bytes(uc.mem_read(source-16,16))==b'\xa1'*16 and bytes(uc.mem_read(source+0x230,16))==b'\xa2'*16,'Lifecycle source object guards')
        require(bytes(uc.mem_read(target-16,16))==b'\xc1'*16 and bytes(uc.mem_read(target+0x230,16))==b'\xc2'*16,'Lifecycle copy object guards')
        for at,length in state['allocations'].items():
            require(bytes(uc.mem_read(at-16,16))==b'\xa5'*16 and bytes(uc.mem_read(at+length,16))==b'\xa6'*16,'Lifecycle heap guards')
    operation.summary=summary
    return operation


def verify():
    spec=importlib.util.spec_from_file_location('character_reader_replay',HERE/'replay-sight-character-other-11316.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.verify(lifecycle=SimpleNamespace(install=install,LIMITS=LIMITS,__file__=__file__))


if __name__=='__main__':print(json.dumps(verify()))
