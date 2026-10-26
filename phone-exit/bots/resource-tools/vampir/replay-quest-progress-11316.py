"""Whole current quest-progress projection; synthetic table and logging, no IO."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run(*,native_lookup=False):
    path=HERE/'knowledge/native-contexts'/('quest-task-lookup-11316.json' if native_lookup else 'quest-progress-11316.json')
    context=json.loads(path.read_text('utf-8'))
    h=load('native-request-harness-11316').make_harness(context['exports'],
        {int(v,16) for v in context['functions'].values()},
        leaves={int(k,16):v for k,v in context['leaves'].items()})
    uc,x,base=h.uc,h.x,h.scratch
    result,progress,wrapper,slots,task,vtable,kind_get,logobject,logtable,logfree=[base+n for n in
        (0x1000,0x2000,0x3000,0x5000,0x6000,0x7000,0x8000,0x9000,0xa000,0xb000)]
    manager,nodes,buckets,hash_get=[base+n for n in (0xc000,0xd000,0xe000,0xf000)]
    selected={};calls=[]

    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,value,size=8):uc.mem_write(at,int(value).to_bytes(size,'little',signed=value<0))
    def integer(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def lookup(machine):
        if integer(reg('RDX'))!=selected['key']:raise ValueError('Quest key forwarding changed')
        put(reg('RCX'),0 if selected['lookup']=='missing' else wrapper)
        calls.append('lookup');h.finish(reg('RCX'))
    def kind(machine):
        if reg('RCX')!=task:raise ValueError('Task virtual receiver changed')
        calls.append('kind');h.finish(selected['kind'])
    def manager_get(machine):calls.append('manager');h.finish(manager)
    def hash_key(machine):
        if integer(reg('RCX'))!=selected['key'] or reg('RDX')!=8 or reg('R8')!=0:
            raise ValueError('Native task lookup hash inputs changed')
        calls.append('hash');h.finish(1)
    def log_format(machine):
        if reg('R8')!=selected['key']:raise ValueError('Diagnostic quest key changed')
        put(reg('RCX'),logobject if selected['log_heap'] else 0)
        calls.append('format');h.finish(reg('RCX'))
    def log_wrap(machine):
        put(reg('RCX'),logobject if selected['log_heap'] else 0)
        calls.append('wrap');h.finish(reg('RCX'))
    def log_emit(machine):
        if reg('RCX')!=0:raise ValueError('Diagnostic level changed')
        calls.append('emit');h.finish()
    def log_release(machine):
        if reg('RCX')!=logobject:raise ValueError('Diagnostic release receiver changed')
        calls.append('release');h.finish()
    def log_destroy(machine):
        if reg('RCX')!=logobject:raise ValueError('Diagnostic destroy receiver changed')
        calls.append('destroy');h.finish()
    for at,callback in ((kind_get,kind),(0x141433340,log_format),
            (0x1414c3070,log_wrap),(0x141584120,log_emit),(logfree,log_release),(0x141483080,log_destroy)):
        h.add_fixture(at,callback)
    if native_lookup:
        h.add_fixture(0x145b547a0,manager_get);h.add_fixture(hash_get,hash_key)
        put(0x14b0c2b00,hash_get)
    else:h.add_fixture(0x145b4be70,lookup)
    put(vtable+0x30,kind_get);put(logobject,logtable);put(logtable+0x10,logfree)
    cases=[]
    # Native uses MOVSX for the incoming byte and only an upper count bound.
    # Allocate guarded negative slots explicitly; this is evidence of that
    # behavior, never permission to accept malformed indexes in runtime.
    for key in (0,110120,0xffffffffffffffff):
        for index in (0,1,2,127,128,255):
            for count in (0,2,128):
                for lookup_case in ('missing','null_task','found'):
                    for heap in (False,True):
                        selected.update(key=key,lookup=lookup_case,kind=7,log_heap=heap)
                        calls.clear()
                        uc.mem_write(result-16,b'\xa1'*16+b'\xcc'*32+b'\xa2'*16)
                        uc.mem_write(progress-16,b'\xb1'*16+bytes(32)+b'\xb2'*16)
                        put(progress+8,index,1)
                        put(progress+0x10,0x12345678abcdef01)
                        put(progress+0x18,0x876543210badf00d)
                        put(wrapper,slots);put(wrapper+8,count,4)
                        uc.mem_write(slots-128*8,bytes(256*8))
                        signed_index=index if index<128 else index-256
                        put(slots+signed_index*8,task if lookup_case=='found' else 0)
                        put(task,vtable);put(task+0x40,0xfedcba9876543210)
                        immutable=[(at,bytes(uc.mem_read(at,size))) for at,size in
                            ((progress-16,64),(wrapper,16),(slots-128*8,2048),(task,80))]
                        if native_lookup:
                            for at,size in ((manager,256),(nodes,64),(buckets,8)):
                                uc.mem_write(at-16,b'\xc1'*16+bytes(size)+b'\xc2'*16)
                            empty=lookup_case=='missing' and count==0
                            put(manager+0x68,nodes);put(manager+0x70,2 if not empty or heap else 0,4)
                            put(manager+0x9c,2 if empty and heap else 0,4)
                            put(manager+0xa8,buckets if heap else 0);put(manager+0xb0,2,4)
                            bucket_base=buckets if heap else manager+0xa0
                            put(bucket_base,-1,4);put(bucket_base+4,0,4)
                            put(nodes,key^2);put(nodes+0x18,1,4)
                            put(nodes+32,key^4 if lookup_case=='missing' else key)
                            # Value is the TArray header *inside* the second
                            # native map node, not an independent wrapper fixture.
                            put(nodes+40,slots);put(nodes+48,count,4);put(nodes+52,count,4)
                            put(nodes+56,-1,4)
                            immutable.extend((at-16,bytes(uc.mem_read(at-16,size+32)))
                                for at,size in ((manager,256),(nodes,64),(buckets,8)))
                        uc.reg_write(x.UC_X86_REG_RDX,key);uc.reg_write(x.UC_X86_REG_R8,progress)
                        returned=h.call(0x145de4610,result)
                        found=lookup_case=='found' and signed_index<count
                        expected=bytearray(b'\xcc'*32)
                        if found:
                            struct.pack_into('<QBB',expected,0,0xfedcba9876543210,7,index)
                            struct.pack_into('<II',expected,12,0xabcdef01,0x0badf00d)
                        else:
                            struct.pack_into('<QH',expected,0,0,0xff1f)
                            struct.pack_into('<Q',expected,12,0)
                        struct.pack_into('<Q',expected,24,0)
                        if returned!=result or bytes(uc.mem_read(result,32))!=bytes(expected):
                            raise ValueError('Native progress projection differs')
                        if bytes(uc.mem_read(result-16,16))!=b'\xa1'*16 or bytes(uc.mem_read(result+32,16))!=b'\xa2'*16:
                            raise ValueError('Projection output guard changed')
                        expected_calls=(['manager','hash'] if native_lookup else ['lookup'])+(
                            ['kind'] if found else ['format','wrap','emit']+(['release','destroy'] if heap else []))
                        if calls!=expected_calls:raise ValueError('Projection lookup/diagnostic lifecycle differs')
                        for at,expected_bytes in immutable:
                            if bytes(uc.mem_read(at,len(expected_bytes)))!=expected_bytes:raise ValueError('Input or guard mutated')
                        cases.append(dict(key=key,index=index,signed_index=signed_index,count=count,
                            lookup=lookup_case,log_heap=heap,found=found,
                            lookup_storage=('external' if heap else 'inline') if native_lookup else 'fixture'))
    audit=load('audit-client-release')
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),
        native_execution=True,native_lookup=native_lookup,network_used=False,exports=h.evidence,cases=cases,
        limits=[('Whole 145de4610 / 145b4be70 and pointer getter execute; manager getter, hash dispatch, task kind and diagnostics are fixtures.' if native_lookup else
            'Whole 145de4610 and pointer getter execute; table lookup, task kind and diagnostic helpers are fixtures.'),
            'Synthetic task array, including explicitly allocated negative slots; no runtime acceptance of negative indexes.',
            'Successful output: task+0x40, virtual kind, original index byte, low32 of progress+0x10/+0x18, zero+0x18.',
            'Failure output: zero key, kind1F/indexFF, zero counters and tail; padding remains untouched.',
            'Not a whole QuestSync application, selected task proof, HUD callback, movement or server acceptance.'])
    return audit.save_snapshot(h.root/'code-clues'/('quest-task-lookup-11316' if native_lookup else 'quest-progress-11316'),report),report


if __name__=='__main__':
    path,report=run();print(json.dumps(dict(report=str(path),cases=len(report['cases']),found=sum(c['found'] for c in report['cases']))))
