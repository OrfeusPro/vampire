"""Preallocated native sparse insert and absent/zero service-group gate; no IO."""
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
    path=HERE/'knowledge/native-contexts/quest-sparse-insert-11316.json';context=json.loads(path.read_text('utf-8'))
    h=load('native-request-harness-11316').make_harness(context['exports'],{int(a,16) for a in context['functions']})
    if h.sha!=context['source_sha256'] or any(f.get('direct_flow_coverage_complete') is not True for f in h.fragments):
        raise ValueError('Sparse/gate export coverage differs')
    uc,x,base=h.uc,h.x,h.scratch
    manager,nodes,buckets,output,keyptr,arg,filterobj,row=[base+n for n in (0x1000,0x3000,0x5000,0x7000,0x8000,0x9000,0xa000,0xb000)]
    selected={};calls=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def integer(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,value,size=8):uc.mem_write(at,int(value).to_bytes(size,'little',signed=value<0))
    def bit_append(machine):
        if reg('RCX')!=manager+0x10 or reg('RDX')!=0:raise ValueError('Bit append inputs differ')
        n=integer(manager+0x28,4)
        if n!=selected['count']:raise ValueError('Bit append count differs')
        put(manager+0x28,n+1,4);calls.append('bit_append');h.finish(n)
    def construct(machine):
        if reg('RCX')!=arg or reg('RDX')!=selected['node']:raise ValueError('Primary constructor args differ')
        uc.mem_write(reg('RDX'),bytes(200));put(reg('RDX'),integer(integer(arg)))
        calls.append('construct');h.finish(reg('RDX'))
    def duplicate(machine):
        if reg('RCX')!=manager or reg('RDX')!=selected['hash'] or reg('R8')!=selected['node']:
            raise ValueError('Duplicate check inputs differ')
        if integer(reg('R9'),4)!=selected['slot']:raise ValueError('Duplicate slot differs')
        calls.append('duplicate');h.finish(0)
    def parse(machine):
        if reg('RCX')!=row or reg('RDX')!=selected['column']:raise ValueError('Group column inputs differ')
        calls.append('parse_zero');h.finish(0)
    for at,callback in ((0x141429680,bit_append),(0x145b48860,construct),(0x145b74820,duplicate),(0x143b7f400,duplicate),(0x1445f5eb0,parse)):
        h.add_fixture(at,callback)
    cases=[]
    for primary,count,free,external,key,hash_value in itertools.product((False,True),(1,2),(False,True),(False,True),(0,110120005,2**64-1),(0,1)):
        stride=200 if primary else 32;slot=count-1 if free else count;node=nodes+slot*stride
        selected.update(count=count,slot=slot,node=node,hash=hash_value);calls.clear()
        uc.mem_write(manager-16,b'M'*16+bytes(128)+b'N'*16);uc.mem_write(nodes-16,b'G'*16+b'Z'*(stride*5)+b'H'*16)
        put(manager,nodes);put(manager+8,count,4);put(manager+12,5,4);put(manager+0x28,count,4);put(manager+0x2c,128,4)
        put(manager+0x10,((1<<count)-1)&~((1<<slot) if free else 0),4)
        put(manager+0x30,slot if free else -1,4);put(manager+0x34,int(free),4)
        put(manager+0x40,buckets if external else 0);put(manager+0x48,2,4)
        bucket_base=buckets if external else manager+0x38
        put(bucket_base,-1,4);put(bucket_base+4,0,4)
        if free:put(node+4,-1,4)
        put(keyptr,key);put(arg,keyptr);uc.mem_write(output-16,b'A'*16+b'\xcc'*8+b'B'*16)
        before_nodes=bytearray(uc.mem_read(nodes-16,stride*5+32));before_manager=bytearray(uc.mem_read(manager-16,160))
        before_buckets=bytearray(uc.mem_read(bucket_base,8))
        uc.reg_write(x.UC_X86_REG_RDX,output);uc.reg_write(x.UC_X86_REG_R8,hash_value);uc.reg_write(x.UC_X86_REG_R9,arg)
        put(base+0x38000+40,0)
        try:returned=h.call(0x145b4a420 if primary else 0x145b48b50,manager)
        except Exception as error:
            raise ValueError(f'Insert case {primary,count,free,external,key,hash_value}: RIP={reg("RIP"):x}, RSP={reg("RSP"):x}, calls={calls}') from error
        if returned!=output or integer(output,4)!=slot:raise ValueError('Sparse slot result differs')
        expected=bytearray(bytes(200) if primary else before_nodes[16+slot*stride:16+(slot+1)*stride])
        struct.pack_into('<Q',expected,0,key)
        if not primary:struct.pack_into('<QQ',expected,8,0,0)
        next_offset=0xc0 if primary else 0x18
        struct.pack_into('<iI',expected,next_offset,-1 if hash_value==0 else 0,hash_value)
        before_nodes[16+slot*stride:16+(slot+1)*stride]=expected
        if bytes(uc.mem_read(nodes-16,stride*5+32))!=bytes(before_nodes):raise ValueError('Node/guards differ')
        struct.pack_into('<I',before_manager,16+0x10,(((1<<count)-1)&~((1<<slot) if free else 0))|(1<<slot))
        if free:
            struct.pack_into('<iI',before_manager,16+0x30,-1,0)
        else:
            struct.pack_into('<I',before_manager,16+8,count+1);struct.pack_into('<I',before_manager,16+0x28,count+1)
        if not external:struct.pack_into('<i',before_manager,16+0x38+hash_value*4,slot)
        if bytes(uc.mem_read(manager-16,160))!=bytes(before_manager):raise ValueError('Map/guards differ')
        struct.pack_into('<i',before_buckets,hash_value*4,slot)
        if bytes(uc.mem_read(bucket_base,8))!=bytes(before_buckets):raise ValueError('Bucket linking differs')
        if calls!=(([] if free else ['bit_append'])+(['construct'] if primary else [])+['duplicate']):raise ValueError('Insert callback order differs')
        if bytes(uc.mem_read(output-16,16))!=b'A'*16 or bytes(uc.mem_read(output+8,16))!=b'B'*16:raise ValueError('Output guards differ')
        cases.append(dict(primary=primary,count=count,reused_free_slot=free,external=external,key=str(key),hash=hash_value,slot=slot))
    gates=[]
    for column in (-1,0,16,32767):
        selected['column']=column;calls.clear();uc.mem_write(filterobj,bytes(32));put(filterobj+8,column,2)
        uc.reg_write(x.UC_X86_REG_RDX,row);uc.reg_write(x.UC_X86_REG_RAX,0x12345678)
        value=h.call(0x145a4d2f0,filterobj)
        if value&255 or calls!=([] if column==-1 else ['parse_zero']):raise ValueError('Absent/zero filter path differs')
        gates.append(dict(column=column,parsed_value=0 if column!=-1 else None,skip=False))
    audit=load('audit-client-release');result=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),
        exports=h.evidence,insertion_cases=cases,filter_cases=gates,network_used=False,order_admitted=False,limits=context['limits'])
    target=audit.save_snapshot(h.root/'code-clues/quest-sparse-insert-11316',result);return target,result


if __name__=='__main__':
    target,result=run();print(json.dumps(dict(artifact=str(target),insertions=len(result['insertion_cases']),filter_cases=len(result['filter_cases'])),ensure_ascii=False))
