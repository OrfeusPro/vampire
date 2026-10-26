"""Native rehash/occupied iteration and growth; bounded allocator boundaries."""
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    context_path=HERE/'knowledge/native-contexts/quest-map-growth-11316.json'
    context=json.loads(context_path.read_text('utf-8'))
    h=load('native-request-harness-11316').make_harness(context['exports'],{int(a,16) for a in context['functions']},
        leaves={int(a,16):b for a,b in context['leaves'].items()})
    if h.sha!=context['source_sha256'] or any(f.get('block_coverage_complete') is not True for f in h.fragments):
        raise ValueError('Growth source/export differs')
    uc,x,base=h.uc,h.x,h.scratch
    manager,nodes,flags,buckets,oldbuckets,hashfn,newnodes=[base+n for n in (0x1000,0x3000,0x9000,0xa000,0xb000,0xc000,0x10000)]
    selected={};calls=[];hashes=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def integer(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,n,size=8):uc.mem_write(at,int(n).to_bytes(size,'little',signed=n<0))
    def allocate_buckets(machine):
        if (reg('RCX'),reg('RDX'),reg('R8'),reg('R9'))!=(manager+0x38,0,selected['bucket_count'],4):
            raise ValueError('Bucket allocation arguments differ')
        put(manager+0x40,buckets if selected['bucket_count']>2 else 0)
        calls.append('allocate_buckets');h.finish()
    def free_buckets(machine):
        if (reg('RCX'),reg('RDX'),reg('R8'),reg('R9'))!=(manager+0x40,0,0,4):raise ValueError('Bucket free differs')
        put(manager+0x40,0);calls.append('free_buckets');h.finish()
    def hash_key(machine):
        if reg('RDX')!=8:raise ValueError('Hash length differs')
        key=integer(reg('RCX'));hashes.append(key);h.finish(key&3)
    def resize(machine):
        expected_size=selected['capacity']*selected['stride']
        if (reg('RCX'),reg('RDX'),reg('R8'))!=(selected['old_pointer'],expected_size,8):raise ValueError('Realloc arguments differ')
        uc.mem_write(newnodes-16,b'L'*16+bytes(expected_size)+b'R'*16)
        if selected['old_pointer']:uc.mem_write(newnodes,bytes(uc.mem_read(nodes,selected['old_count']*selected['stride'])))
        calls.append('realloc');h.finish(newnodes)
    for at,callback in ((0x141436bc0,allocate_buckets),(0x141436cc0,free_buckets),(hashfn,hash_key),(0x1414923d0,resize)):
        h.add_fixture(at,callback)
    put(0x14b0c2b00,hashfn);put(0x14b2f01c8,0)  # Exact size-provider RIP target from pinned leaf.
    rehash=[]
    patterns=[(0,[]),(1,[0]),(4,[0,1,2,3]),(6,[0,2,5]),(35,[0,31,32,34])]
    for primary,(count,occupied),external_flags,old_external,bucket_count in itertools.product((False,True),patterns,(False,True),(False,True),(1,2,16)):
        stride=200 if primary else 32;next_offset=0xc0 if primary else 0x18
        selected.update(bucket_count=bucket_count);calls.clear();hashes.clear()
        uc.mem_write(manager-16,b'A'*16+bytes(128)+b'B'*16);uc.mem_write(nodes-16,b'C'*16+b'\x5a'*(max(count,1)*stride)+b'D'*16)
        uc.mem_write(flags,b'\x00'*16);uc.mem_write(buckets-16,b'E'*16+bytes(64)+b'F'*16)
        put(manager,nodes);put(manager+8,count,4);put(manager+0x28,count,4);put(manager+0x34,count-len(occupied),4)
        put(manager+0x20,flags if external_flags else 0);put(manager+0x40,oldbuckets if old_external else 0);put(manager+0x48,bucket_count,4)
        bitbase=flags if external_flags else manager+0x10
        for i in occupied:
            put(bitbase+(i//32)*4,integer(bitbase+(i//32)*4,4)|(1<<(i%32)),4)
        keys={i:110120005+i*4 for i in occupied}  # Deliberate hash collision chain.
        for i,key in keys.items():put(nodes+i*stride,key)
        expected_nodes=bytearray(uc.mem_read(nodes-16,max(count,1)*stride+32));before_flags=bytes(uc.mem_read(flags,16))
        expected_manager=bytearray(uc.mem_read(manager-16,160))
        active_buckets=buckets if bucket_count>2 else manager+0x38
        heads=[-1]*bucket_count
        for i in occupied:
            bucket=(keys[i]&3)&(bucket_count-1)
            struct.pack_into('<iI',expected_nodes,16+i*stride+next_offset,heads[bucket],bucket);heads[bucket]=i
        h.call(0x145b73290 if primary else 0x145b72e70,manager)
        if hashes!=[keys[i] for i in occupied]:raise ValueError('Occupied slot order differs')
        if bytes(uc.mem_read(nodes-16,len(expected_nodes)))!=bytes(expected_nodes):raise ValueError('Rehash changed payload/slots/guards')
        put_expected=struct.pack('<Q',buckets if bucket_count>2 else 0)
        expected_manager[16+0x40:16+0x48]=put_expected
        if bucket_count<=2:
            for i,head in enumerate(heads):struct.pack_into('<i',expected_manager,16+0x38+i*4,head)
        if bytes(uc.mem_read(manager-16,160))!=bytes(expected_manager) or bytes(uc.mem_read(flags,16))!=before_flags:
            raise ValueError('Rehash changed map/bitset metadata')
        if list(struct.unpack('<'+'i'*bucket_count,uc.mem_read(active_buckets,bucket_count*4)))!=heads:raise ValueError('Rehash bucket chain differs')
        expected_bucket_storage=bytearray(b'E'*16+bytes(64)+b'F'*16)
        if bucket_count>2:
            for i,head in enumerate(heads):struct.pack_into('<i',expected_bucket_storage,16+i*4,head)
        if bytes(uc.mem_read(buckets-16,96))!=bytes(expected_bucket_storage):raise ValueError('Bucket storage guards differ')
        if calls!=(['free_buckets'] if old_external else [])+['allocate_buckets']:raise ValueError('Bucket lifecycle differs')
        rehash.append(dict(primary=primary,count=count,occupied=occupied,external_flags=external_flags,old_external=old_external,buckets=bucket_count))
    growth=[]
    for primary,old_count,old_capacity in itertools.product((False,True),(0,1,4,33),(0,64)):
        stride=200 if primary else 32;capacity=max(4,old_count) if old_capacity==0 else old_count+(old_count*3>>3)+16
        selected.update(stride=stride,capacity=capacity,old_count=old_count,old_pointer=nodes if old_capacity else 0);calls.clear()
        uc.mem_write(manager-16,b'S'*16+bytes(128)+b'T'*16);uc.mem_write(nodes-16,b'U'*16+b'\x6b'*(max(old_count,1)*stride)+b'V'*16)
        put(manager,selected['old_pointer']);put(manager+8,old_count,4);put(manager+12,old_capacity,4)
        before=bytearray(uc.mem_read(manager-16,160));oldbytes=bytes(uc.mem_read(nodes-16,max(old_count,1)*stride+32))
        uc.reg_write(x.UC_X86_REG_RDX,old_count);h.call(0x1416166c0 if primary else 0x141437520,manager)
        struct.pack_into('<Q',before,16,newnodes);struct.pack_into('<I',before,28,capacity)
        if calls!=['realloc'] or bytes(uc.mem_read(manager-16,160))!=bytes(before):raise ValueError('Growth metadata differs')
        if bytes(uc.mem_read(nodes-16,len(oldbytes)))!=oldbytes:raise ValueError('Growth modified old allocation')
        if selected['old_pointer'] and bytes(uc.mem_read(newnodes,old_count*stride))!=oldbytes[16:16+old_count*stride]:raise ValueError('Fixture relocation copy differs')
        if bytes(uc.mem_read(newnodes-16,16))!=b'L'*16 or bytes(uc.mem_read(newnodes+capacity*stride,16))!=b'R'*16:raise ValueError('Growth allocation guards differ')
        growth.append(dict(primary=primary,count=old_count,old_capacity=old_capacity,new_capacity=capacity))
    audit=load('audit-client-release');report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(context_path),
        exports=h.evidence,rehash_cases=rehash,growth_cases=growth,network_used=False,order_admitted=False,limits=context['limits'])
    target=audit.save_snapshot(h.root/'code-clues/quest-map-growth-11316',report);return target,report


if __name__=='__main__':
    path,result=run();print(json.dumps(dict(artifact=str(path),rehash=len(result['rehash_cases']),growth=len(result['growth_cases'])),ensure_ascii=False))
