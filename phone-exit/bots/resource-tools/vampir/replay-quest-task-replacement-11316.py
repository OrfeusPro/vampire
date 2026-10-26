"""Whole kind-6 factory and replacement, native refcounts, explicit boundaries."""
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
    audit=load('audit-client-release')
    context_path=HERE/'knowledge/native-contexts/quest-task-replacement-11316.json'
    context=json.loads(context_path.read_text('utf-8'));base_path=context_path.parent/context['base_context']
    if audit.sha256(base_path)!=context['base_context_sha256']:raise ValueError('Base context differs')
    prior=json.loads(base_path.read_text('utf-8'))
    functions={int(a,16) for a in list(prior['functions'].values())+context['additional_functions']}
    exports={k:v for k,v in prior['exports'].items() if k not in context['superseded_exports']}
    h=load('native-request-harness-11316').make_harness(dict(exports,**context['additional_exports']),functions,
        leaves={int(k,16):v for k,v in prior['leaves'].items()})
    if h.sha!=context['source_sha256'] or any(f.get('block_coverage_complete') is not True for f in h.fragments):
        raise ValueError('Replacement source/export differs')
    if next(f for f in h.fragments if f['address']=='0x1455b8ff0').get('direct_flow_coverage_complete') is not True:
        raise ValueError('Factory native flow coverage missing')
    uc,x,base=h.uc,h.x,h.scratch
    record,oldtask,oldctrl,data,progress,oldtable=[base+n for n in (0x1000,0x3000,0x4000,0x6000,0x7003,0x9000)]
    events=[];selected={};blocks=[];cursor=[base+0x10000]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def integer(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,value,size=8):uc.mem_write(at,int(value).to_bytes(size,'little'))
    def bounded(at,size):
        if not base<=at<=base+0x40000-size:raise ValueError('Fixture write outside scratch')
    def allocate(machine):
        size=reg('RCX')
        if size not in (0x2b0,0x100,0x18):raise ValueError('Unexpected factory allocation')
        if size==0x2b0 and selected['fail']:
            events.append('primary_allocation_failed');h.finish(0);return
        at=cursor[0]+16;cursor[0]+=((size+15)//16)*16+32
        if cursor[0]>=base+0x30000:raise ValueError('Heap fixture budget')
        uc.mem_write(at-16,b'G'*(size+32));uc.mem_write(at,b'\xcd'*size)
        blocks.append((at,size));events.append('allocate_'+hex(size));h.finish(at)
    def zero(machine):
        at,value,size=reg('RCX'),reg('RDX'),reg('R8');bounded(at,size)
        if value!=0 or not any(p<=at and at+size<=p+n for p,n in blocks):raise ValueError('Invalid memset boundary')
        uc.mem_write(at,bytes(size));h.finish(at)
    def delegate(machine):
        at=reg('RCX');bounded(at,24);uc.mem_write(at,bytes(24));events.append('delegate_init');h.finish(at)
    def empty_string(machine):
        at=reg('RCX');bounded(at,16)
        literal=h.image.offset(reg('RDX')-h.image.pe.base)
        if h.raw[literal:literal+2]!=bytes(2):raise ValueError('Nonempty constructor string')
        uc.mem_write(at,bytes(16));events.append('empty_string');h.finish(at)
    def nested_value(machine):
        if reg('RDX')!=0:raise ValueError('Nested init argument differs')
        bounded(reg('RCX'),8);put(reg('RCX'),0);events.append('nested_init');h.finish()
    def task_data(machine):
        if reg('RCX')!=selected['key']:raise ValueError('Task key lookup differs')
        events.append('task_data');h.finish(data)
    def init_task(machine):
        task=reg('RCX')
        if bytes(uc.mem_read(task+0x20,32))!=selected['raw'] or integer(task+0x40)!=data:
            raise ValueError('Task initialized before copied progress/data')
        events.append('task_init');h.finish()
    def post_task(machine):
        if bytes(uc.mem_read(reg('RCX')+0x20,32))!=selected['raw']:raise ValueError('Post init progress differs')
        events.append('task_post');h.finish()
    def owner_bind(machine):
        if integer(reg('RDX'))!=integer(record+8) or integer(reg('RDX')+8)!=0:raise ValueError('Owner context differs')
        selected['newtask']=reg('RCX');events.append('owner_bind');h.finish()
    def start_task(machine):
        if reg('RCX')!=integer(record+0x30) or integer(record+0x28,1)!=selected['old_state']:
            raise ValueError('Start callback receiver/state differs')
        events.append('start');h.finish()
    def advance_task(machine):
        if reg('RCX')!=oldtask or integer(record+0x30)!=oldtask:raise ValueError('Old advance order differs')
        events.append('advance_old');h.finish()
    def destroy(machine):
        ctrl=reg('RCX')
        if integer(ctrl+8,4)!=0:raise ValueError('Destructor before final strong release')
        events.append('destroy_old' if ctrl==oldctrl else 'destroy_null')
        if ctrl!=oldctrl and integer(ctrl+16)!=0:raise ValueError('Unexpected new controller destruction')
        h.finish()
    def free_control(machine):
        ctrl=reg('RCX')
        if integer(ctrl+12,4)!=0 or reg('RDX')!=1:raise ValueError('Weak controller release differs')
        events.append('free_old' if ctrl==oldctrl else 'free_null');h.finish()
    def enum_provider(machine):events.append('enum_provider_absent');h.finish(0)
    def format_log(machine):
        at=reg('RCX');bounded(at,16);uc.mem_write(at,bytes(16));h.finish(at)
    def emit_log(machine):
        if reg('RCX')!=0:raise ValueError('Log level differs')
        events.append('fallback_log');h.finish()
    def cookie(machine):
        if reg('RCX')!=integer(0x14b271780):raise ValueError('Stack cookie mismatch')
        h.finish()
    fixtures={0x146908950:allocate,0x1487f5ac5:zero,0x1445df680:delegate,0x141426b30:empty_string,
        0x1417f4140:nested_value,0x14546da00:task_data,0x1455d2630:init_task,0x1455d1060:post_task,
        0x1455b5450:owner_bind,0x1455c3eb0:start_task,0x1455c3d00:start_task,
        0x141c9eb30:destroy,0x1414091b0:free_control,0x144aaa8a0:enum_provider,
        0x141433340:format_log,0x1414c3070:format_log,0x141584120:emit_log,0x1487e8ce0:cookie,
        base+0xa000:advance_task}
    for address,callback in fixtures.items():h.add_fixture(address,callback)
    for table,slots in {0x149905340:{0x28:0x1455c3eb0,0x48:0x1455d2630},
                        0x149903d68:{0x28:0x1455c3d00},0x148af6260:{0:0x141c9eb30,8:0x1414091b0}}.items():
        for slot,target in slots.items():
            off=h.image.offset(table+slot-h.image.pe.base)
            if struct.unpack_from('<Q',h.raw,off)[0]!=target:raise ValueError('Lifecycle slot binding differs')
    put(oldtable+0x38,base+0xa000);put(0x14b5e0bc0,0)
    cases=[];mask=(1<<64)-1
    signed=lambda n:n-(1<<64) if n>>63 else n
    modes=[('empty',0,0)]+[(mode,s,w) for mode in ('previous','next') for s,w in ((1,1),(1,2),(2,1))]
    for key,(mode,strong,weak),state,index,fail in itertools.product((0,110120005,mask),modes,(0,2,255),(0,1,255),(False,True)):
        uc.mem_write(base+0x10000,bytes(0x20000));cursor[0]=base+0x10000;blocks.clear();events.clear()
        raw=bytearray((index+i*13)&255 for i in range(32));struct.pack_into('<Q',raw,0,key);raw[8]=6;raw[9]=index;raw=bytes(raw)
        uc.mem_write(record-16,b'R'*128);uc.mem_write(oldtask-16,b'O'*160);uc.mem_write(oldctrl-16,b'C'*64)
        uc.mem_write(progress-16,b'P'*64);uc.mem_write(progress,raw)
        oldkey=(key+(-1 if mode=='previous' else 1))&mask
        put(record+8,12345);put(record+16,0);put(record+0x30,0 if mode=='empty' else oldtask);put(record+0x38,0 if mode=='empty' else oldctrl)
        put(oldtask,oldtable);put(oldtask+0x20,oldkey);put(oldctrl,0x148af6260);put(oldctrl+8,strong,4);put(oldctrl+12,weak,4);put(oldctrl+16,oldtask)
        old_state=2 if index==1 else 0;uc.mem_write(record+0x28,bytes([old_state]));put(data,key)
        before_record=bytearray(uc.mem_read(record-16,128));before_old=bytes(uc.mem_read(oldtask-16,160))
        before_control=bytearray(uc.mem_read(oldctrl-16,64))
        before_input=bytes(uc.mem_read(progress-16,64));selected.update(key=key,raw=raw,fail=fail,old_state=old_state,newtask=None)
        uc.reg_write(x.UC_X86_REG_RDX,state);uc.reg_write(x.UC_X86_REG_R8,progress)
        h.call(0x1455f4a80,record,budget=10000)
        task,control=integer(record+0x30),integer(record+0x38)
        if selected['newtask']!=task or integer(control+8,4)!=1 or integer(control+12,4)!=1 or integer(control+16)!=task:
            raise ValueError('Final task ownership differs')
        if not fail and bytes(uc.mem_read(task+0x20,32))!=raw:raise ValueError('Factory progress copy differs')
        if integer(task)!=(0x149903d68 if fail else 0x149905340):raise ValueError('Factory task type differs')
        if fail:
            if integer(task+0x20)!=0 or integer(task+0x28,2)!=0xff1f:raise ValueError('Fallback progress differs')
            if any(events.count(e)!=1 for e in ('primary_allocation_failed','fallback_log','destroy_null','free_null')):
                raise ValueError('Fallback/temporary ownership differs')
            if 'task_data' in events or 'task_init' in events or 'task_post' in events:raise ValueError('Fallback used success path')
        elif any(events.count(e)!=1 for e in ('task_data','task_init','task_post')) or 'fallback_log' in events or 'destroy_null' in events:
            raise ValueError('Success factory initialization differs')
        expected_index=255 if fail else index
        if h.call(0x1455e7510,record)&255!=expected_index:raise ValueError('Created sender index differs')
        advanced=mode!='empty' and signed(oldkey)<signed(key)
        if events.count('advance_old')!=int(advanced) or events.count('start')!=int(state==2):raise ValueError('Lifecycle branch differs')
        if events.count('destroy_old')!=int(mode!='empty' and strong==1) or events.count('free_old')!=int(mode!='empty' and strong==weak==1):
            raise ValueError('Old controller lifecycle differs')
        if mode!='empty' and (integer(oldctrl+8,4)!=strong-1 or integer(oldctrl+12,4)!=weak-int(strong==1)):
            raise ValueError('Old refcount differs')
        if mode!='empty':struct.pack_into('<II',before_control,24,strong-1,weak-int(strong==1))
        if bytes(uc.mem_read(oldctrl-16,64))!=bytes(before_control):raise ValueError('Old controller/guards changed')
        before_record[16+0x28]=state;struct.pack_into('<QQ',before_record,16+0x30,task,control)
        if bytes(uc.mem_read(record-16,128))!=bytes(before_record) or bytes(uc.mem_read(oldtask-16,160))!=before_old:
            raise ValueError('Record/old task guard changed')
        if bytes(uc.mem_read(progress-16,64))!=before_input:raise ValueError('Input guard changed')
        for at,size in blocks:
            if bytes(uc.mem_read(at-16,16))!=b'G'*16 or bytes(uc.mem_read(at+size,16))!=b'G'*16:raise ValueError('Heap guard changed')
        if 'start' in events and events.index('owner_bind')>events.index('start'):raise ValueError('Start preceded owner binding')
        if 'destroy_old' in events and events.index('destroy_old')>next(i for i,e in enumerate(events) if e.startswith('allocate_') or e=='primary_allocation_failed'):
            raise ValueError('Old release followed new allocation')
        cases.append(dict(key=str(key),mode=mode,strong=strong,weak=weak,state=state,index=index,primary_allocation_failed=fail,
            events=events.copy(),final_control_strong=1,final_control_weak=1))
    result=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(context_path),
        evidence=h.evidence,case_count=len(cases),cases=cases,network_used=False,
        native_functions=[hex(a) for a in sorted(functions)]+['0x1455e7510'],fixture_addresses=[hex(a) for a in fixtures],limits=context['limits'])
    target=audit.save_snapshot(h.root/'code-clues/quest-task-replacement-11316',result);return target,result


if __name__=='__main__':
    path,result=run();print(json.dumps(dict(artifact=str(path),cases=result['case_count']),ensure_ascii=False))
