"""Whole FindOrAdd/insert/grow/rehash chain, bounded external services."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    path=HERE/'knowledge/native-contexts/quest-map-chain-11316.json';context=json.loads(path.read_text('utf-8'))
    h=load('native-request-harness-11316').make_harness(context['exports'],{int(a,16) for a in context['functions']},
        leaves={int(a,16):b for a,b in context['leaves'].items()})
    if h.sha!=context['source_sha256'] or any(f.get('block_coverage_complete') is not True for f in h.fragments):
        raise ValueError('Chain source/export differs')
    uc,x,base=h.uc,h.x,h.scratch
    manager,keyptr,hashfn=base+0x1000,base+0x2000,base+0x3000
    cursor=[base+0x10000];blocks={};calls={};selected={};hashes=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def integer(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,n,size=8):uc.mem_write(at,int(n).to_bytes(size,'little',signed=n<0))
    def count(name):calls[name]=calls.get(name,0)+1
    def allocate(size):
        at=(cursor[0]+31)&~15;cursor[0]=at+((size+15)&~15)+16
        if size<=0 or cursor[0]>=base+0x33000:raise ValueError('Scratch allocation budget')
        uc.mem_write(at-16,b'L'*16+bytes(size)+b'R'*16);blocks[at]=size;return at
    def resize(machine):
        old,size,align=reg('RCX'),reg('RDX'),reg('R8')
        if align!=8 or size%selected['stride'] or (old and old not in blocks):raise ValueError('Node resize contract differs')
        at=allocate(size)
        if old:uc.mem_write(at,bytes(uc.mem_read(old,min(size,blocks[old]))))
        count('resize');h.finish(at)
    def bucket_allocate(machine):
        if (reg('RCX'),reg('RDX'),reg('R9'))!=(manager+0x38,0,4):raise ValueError('Bucket allocation differs')
        n=reg('R8');put(manager+0x40,allocate(n*4) if n>2 else 0);count('bucket_allocate');h.finish()
    def bucket_free(machine):
        if (reg('RCX'),reg('RDX'),reg('R8'),reg('R9'))!=(manager+0x40,0,0,4):raise ValueError('Bucket free differs')
        put(manager+0x40,0);count('bucket_free');h.finish()
    def bit_append(machine):
        if reg('RCX')!=manager+0x10 or reg('RDX')!=0:raise ValueError('Bit append differs')
        old=integer(manager+0x28,4)
        if old>=128:raise ValueError('Inline bitset budget')
        put(manager+0x28,old+1,4);count('bit_append');h.finish(old)
    def construct(machine):
        node=reg('RDX');key=integer(integer(reg('RCX')))
        uc.mem_write(node,bytes(200));put(node,key);count('construct');h.finish(node)
    def duplicate(machine):
        if reg('RCX')!=manager:raise ValueError('Duplicate map receiver differs')
        count('duplicate');h.finish(0)
    def hash_key(machine):
        if reg('RDX')!=8:raise ValueError('Hash input length differs')
        hashes.append(integer(reg('RCX')));h.finish(1)  # Deliberate collision chain for all keys.
    for address,callback in ((0x1414923d0,resize),(0x141436bc0,bucket_allocate),(0x141436cc0,bucket_free),
            (0x141429680,bit_append),(0x145b48860,construct),(0x145b74820,duplicate),(0x143b7f400,duplicate),(hashfn,hash_key)):
        h.add_fixture(address,callback)
    put(0x14b0c2b00,hashfn);put(0x14b2f01c8,0)
    runs=[];orders=[list(range(70)),list(reversed(range(70))),[(i*37)%70 for i in range(70)]]
    for primary in (False,True):
      for order in orders:
        stride=200 if primary else 32;selected['stride']=stride;cursor[0]=base+0x10000;blocks.clear();calls.clear()
        uc.mem_write(manager-16,b'A'*16+bytes(128)+b'B'*16);put(manager+0x2c,128,4);put(manager+0x30,-1,4)
        expected={};capacities=[];bucket_counts=[]
        def find(key):
            put(keyptr,key);uc.reg_write(x.UC_X86_REG_RDX,1);uc.reg_write(x.UC_X86_REG_R8,keyptr)
            return h.call(0x145b4ab90 if primary else 0x145b4ad00,manager,budget=50000)
        for index,number in enumerate(order):
            key=110120000+number;value=find(key)
            if integer(manager+8,4)!=index+1 or integer(manager+0x34,4)!=0 or value!=integer(manager)+index*stride+8:
                raise ValueError('FindOrAdd insertion/slot/count differs')
            payload=bytes((number+i*11)&255 for i in range(184 if primary else 16));uc.mem_write(value,payload);expected[key]=payload
            capacities.append(integer(manager+12,4));bucket_counts.append(integer(manager+0x48,4))
            counts_before=calls.copy();before=bytes(uc.mem_read(manager,128));nodes_before=bytes(uc.mem_read(integer(manager),(index+1)*stride))
            if find(key)!=value or calls!=counts_before or bytes(uc.mem_read(manager,128))!=before or bytes(uc.mem_read(integer(manager),(index+1)*stride))!=nodes_before:
                raise ValueError('Existing key allocated/changed map')
            for slot,prior in enumerate(order[:index+1]):
                at=integer(manager)+slot*stride
                if integer(at)!=110120000+prior or bytes(uc.mem_read(at+8,len(expected[110120000+prior])))!=expected[110120000+prior]:
                    raise ValueError('Growth/rehash reordered or altered record payload')
        # Existing lookup through the resulting collision chain must preserve all key→value bindings.
        counts_before=calls.copy()
        for slot,number in enumerate(order):
            if find(110120000+number)!=integer(manager)+slot*stride+8:raise ValueError('Final collision lookup differs')
        if calls!=counts_before:raise ValueError('Final lookup triggered mutation callbacks')
        # Explicit final rehash: actual iterator visits original insertion-slot order.
        hashes.clear();h.call(0x145b73290 if primary else 0x145b72e70,manager)
        if hashes!=[110120000+n for n in order]:raise ValueError('Final occupied iteration differs')
        for slot,number in enumerate(order):
            at=integer(manager)+slot*stride;key=110120000+number
            if integer(at)!=key or bytes(uc.mem_read(at+8,len(expected[key])))!=expected[key]:
                raise ValueError('Final rehash changed key/payload')
        if integer(manager+0x28,4)!=70 or bytes(uc.mem_read(manager+0x10,12))!=(2**70-1).to_bytes(12,'little'):
            raise ValueError('Occupied bitset differs after chain')
        if calls.get('resize',0)<3 or len(set(bucket_counts))<3:raise ValueError('Chain missed growth/rehash transitions')
        for at,size in blocks.items():
            if bytes(uc.mem_read(at-16,16))!=b'L'*16 or bytes(uc.mem_read(at+size,16))!=b'R'*16:raise ValueError('Heap guard changed')
        if bytes(uc.mem_read(manager-16,16))!=b'A'*16 or bytes(uc.mem_read(manager+128,16))!=b'B'*16:raise ValueError('Map guard changed')
        runs.append(dict(primary=primary,keys=[str(110120000+n) for n in order],insertions=70,existing_lookups=140,
            callbacks=calls.copy(),capacity_transitions=sorted(set(capacities)),bucket_transitions=sorted(set(bucket_counts))))
    audit=load('audit-client-release');report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),
        exports=h.evidence,runs=runs,network_used=False,order_admitted=False,limits=context['limits'])
    target=audit.save_snapshot(h.root/'code-clues/quest-map-chain-11316',report);return target,report


if __name__=='__main__':
    target,result=run();print(json.dumps(dict(artifact=str(target),runs=len(result['runs']),insertions=sum(r['insertions'] for r in result['runs'])),ensure_ascii=False))
