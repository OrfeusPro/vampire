"""Existing-task state application with actual virtual copy/getter, no game IO."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    context_path=HERE/'knowledge/native-contexts/quest-state-application-11316.json'
    context=json.loads(context_path.read_text('utf-8'))
    h=load('native-request-harness-11316').make_harness(context['exports'],
        {int(a,16) for a in context['functions'].values()},leaves={int(k,16):v for k,v in context['leaves'].items()})
    if h.sha!=context['source_sha256'] or any(f.get('block_coverage_complete') is not True for f in h.fragments):
        raise ValueError('Incomplete state application binding')
    # All 23 reviewed task tables, including factory case 6's separately
    # exported constructor, share the same exact virtual-copy leaf.
    for table in context['task_tables']:
        offset=h.image.offset(int(table,16)-h.image.pe.base)
        if struct.unpack_from('<Q',h.raw,offset+0x10)[0]!=0x1455cec20:raise ValueError('Task copy slot differs')
    factory=next(f for f in h.fragments if f['address']=='0x1455b8ff0')
    anchors={0x1455b9fec:'410f1007',0x1455b9ff0:'410f104f10',0x1455b9ff5:'0f114620',0x1455b9ff9:'0f114e30'}
    instructions={int(r['address'],16):r['bytes'] for r in factory['instructions']}
    if any(instructions.get(a)!=b for a,b in anchors.items()):raise ValueError('Factory progress copy differs')
    if factory.get('linear_tail_scan',{}).get('state')!='deferred_to_ghidra':raise ValueError('Factory scan provenance missing')
    uc,x,base=h.uc,h.x,h.scratch
    record,task,vtable,start,update=tuple(base+n for n in (0x1000,0x3000,0x5000,0x6000,0x7000))
    selected={};calls=[]
    def put(at,value):uc.mem_write(at,struct.pack('<Q',value))
    def callback(name):
        def call(machine):
            if uc.reg_read(x.UC_X86_REG_RCX)!=task:raise ValueError('Task callback receiver differs')
            if bytes(uc.mem_read(task+0x20,32))!=selected['raw']:raise ValueError('Callback preceded native copy')
            if uc.mem_read(record+0x28,1)[0]!=selected['old']:raise ValueError('State stored before task callback')
            calls.append(name);h.finish()
        return call
    h.add_fixture(start,callback('start'));h.add_fixture(update,callback('update'))
    put(vtable+0x10,0x1455cec20);put(vtable+0x28,start);put(vtable+0x30,update)
    cases=[]
    for key in (0,110120005,0xffffffffffffffff):
      for old in (0,2,255):
       for state in (0,2,255):
        for index in (0,1,127,128,254,255):
         for alignment in (0,3):
            progress=base+0x9000+alignment
            raw=bytearray((i*17+index)&255 for i in range(32));struct.pack_into('<Q',raw,0,key)
            raw[8]=6;raw[9]=index;raw=bytes(raw)
            uc.mem_write(record-16,b'R'*128);uc.mem_write(task-16,b'T'*160)
            uc.mem_write(progress-16,b'P'*64);uc.mem_write(progress,raw)
            put(task,vtable);put(task+0x20,key);put(record+0x30,task);uc.mem_write(record+0x28,bytes([old]))
            before_record=bytearray(uc.mem_read(record-16,128));before_task=bytearray(uc.mem_read(task-16,160))
            before_progress=bytes(uc.mem_read(progress-16,64));selected.update(raw=raw,old=old);calls.clear()
            uc.reg_write(x.UC_X86_REG_RDX,state);uc.reg_write(x.UC_X86_REG_R8,progress)
            h.call(0x1455f4a80,record,budget=1000)
            expected='start' if old!=2 and state==2 else 'update'
            if calls!=[expected]:raise ValueError('State transition callback differs')
            before_record[16+0x28]=state;before_task[16+0x20:16+0x40]=raw
            if bytes(uc.mem_read(record-16,128))!=bytes(before_record):raise ValueError('Record/guards changed')
            if bytes(uc.mem_read(task-16,160))!=bytes(before_task):raise ValueError('Task/guards changed')
            if bytes(uc.mem_read(progress-16,64))!=before_progress:raise ValueError('Input/guards changed')
            if h.call(0x1455e7510,record)&255!=index:raise ValueError('Sender getter differs after application')
            cases.append(dict(key=str(key),old=old,state=state,index=index,alignment=alignment,callback=expected))
    audit=load('audit-client-release')
    result=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(context_path),
        evidence=h.evidence,task_tables=context['task_tables'],cases=cases,case_count=len(cases),network_used=False,
        static_factory_copy=dict(begin='0x1455b9fec',end='0x1455b9ffd',bytes_copied=32),
        native_functions=['0x1455f4a80','0x1455fd350','0x1455cec20','0x1455e7510'],
        fixtures=['task start callback +0x28','task update callback +0x30'],limits=context['limits'])
    target=audit.save_snapshot(h.root/'code-clues/quest-state-application-11316',result)
    return target,result


if __name__=='__main__':
    target,result=run();print(json.dumps(dict(artifact=str(target),cases=result['case_count']),ensure_ascii=False))
