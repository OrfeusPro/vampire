"""Current kind-6 creation/replacement with native ownership and explicit providers."""
import hashlib
import struct
from types import SimpleNamespace

SOURCE='03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
FUNCTIONS=dict(factory='0x1455b8fe0',constructor='0x1455ab5c0',control='0x1455a9330',
    move='0x141473540',state='0x1455f4a70',progress='0x1455fd340')
GETTER=0x1455e7500
MASK=(1<<64)-1
FIXTURES=dict(allocate='0x14690be10',zero='0x1487f8ca5',delegate='0x1445df7e0',
    empty_string='0x141426b90',nested='0x1417f4470',task_data='0x14546d9d0',
    init_task='0x1455d2620',post_task='0x1455d1050',bind_owner='0x1455b5440',
    start_success='0x1455c3ea0',start_fallback='0x1455c3cf0',destroy='0x141c9ee20',
    free_control='0x141409210',enum_provider='0x144aaa990',format_log='0x1414333a0',
    wrap_log='0x1414c33a0',log='0x141584450',cookie='0x1487ebec0',advance='0x2803e000')
FLAGS=dict(scope='kind6_creation_replacement_and_primary_failure_fallback',
    task_data='fixture',owner_binding='fixture',lifecycle='fixtures',allocation='fixture',
    destructor_effects='fixtures',nested_initialization='fixtures',parent_weak_control='null',
    optional_provider_cache='disabled',control_allocation_failure_executed=False,
    actual_native_refcounts=True,actual_kind6_constructor=True,actual_control_constructor=True,
    actual_shared_move_release=True,other_factory_kinds_executed=False,
    active_task_verified=False,ordered_catalog_verified=False,runtime_admitted=False,
    action_admitted=False,network_used=False)


def cases():
    seeds=((0,'empty',0,0,0,0,0), (0,'previous',1,1,0,2,1),
        (0,'next',1,2,2,255,255),(1,'previous',2,1,2,2,0),
        (0x7fffffffffffffff,'next',1,1,0,2,255),
        (0x8000000000000000,'previous',1,2,2,255,0),
        (MASK,'previous',2,1,0,0,1),(MASK,'next',1,1,2,2,255),
        (110120005,'previous',1,2,0,2,1),(110120005,'next',2,1,2,255,0),
        (1,'empty',0,0,0,2,255),(0x8000000000000000,'empty',0,0,2,255,1))
    return [dict(key=str(key),mode=mode,strong=strong,weak=weak,old_state=old,state=state,
        index=index,primary_failure=failure,alignment=alignment)
        for alignment in (0,3) for failure in (False,True)
        for key,mode,strong,weak,old,state,index in seeds]


def signed(value):return value-(1<<64) if value>>63 else value


def expected(case):
    key=int(case['key']);oldkey=(key+(-1 if case['mode']=='previous' else 1))&MASK
    existing=case['mode']!='empty';advanced=existing and signed(oldkey)<signed(key)
    events=[]
    if advanced:events.append('advance_old')
    if existing and case['strong']==1:
        events.append('destroy_old')
        if case['weak']==1:events.append('free_old')
    if case['primary_failure']:
        events+=['primary_failure','allocate_control','fallback_log','allocate_fallback','allocate_control',
            'destroy_null','free_null']
    else:events+=['allocate_primary','allocate_control','task_data','task_init','task_post']
    events+=['cookie','owner_bind']
    if case['state']==2:events.append('start')
    return dict(case=case,old_key=str(oldkey) if existing else None,advanced=advanced,events=events,
        final_index=255 if case['primary_failure'] else case['index'],
        final_table='0x149906828' if case['primary_failure'] else '0x149907e00',
        final_control=[1,1],old_control=[case['strong']-1,case['weak']-int(case['strong']==1)] if existing else None)


def validate(result):
    rows=[expected(case) for case in cases()]
    count=len(rows);success=sum(not row['case']['primary_failure'] for row in rows)
    failure=count-success
    event_count=lambda name:sum(row['events'].count(name) for row in rows)
    entries={address:count for address in (FUNCTIONS['factory'],FUNCTIONS['state'],FUNCTIONS['progress'],hex(GETTER))}
    entries.update({FUNCTIONS['constructor']:success,FUNCTIONS['control']:count,FUNCTIONS['move']:count*2})
    fixture_counts=dict(allocate=event_count('allocate_primary')+event_count('primary_failure')
            +event_count('allocate_fallback')+event_count('allocate_control'),
        zero=count,delegate=success,empty_string=success,nested=success,
        task_data=success,init_task=success,post_task=success,bind_owner=count,
        start_success=sum(row['case']['state']==2 and not row['case']['primary_failure'] for row in rows),
        start_fallback=sum(row['case']['state']==2 and row['case']['primary_failure'] for row in rows),
        destroy=event_count('destroy_old')+event_count('destroy_null'),
        free_control=event_count('free_old')+event_count('free_null'),enum_provider=failure,
        format_log=failure,wrap_log=failure,log=failure,cookie=count,advance=event_count('advance_old'))
    entries.update({FIXTURES[role]:number for role,number in fixture_counts.items() if number})
    metrics=result.get('metrics',{}) if isinstance(result,dict) else {}
    if (not isinstance(result,dict) or any(result.get(key)!=value for key,value in FLAGS.items())
            or result.get('cases')!=rows
            or set(metrics)!={'call_counts','abi_checks','read_checks','write_checks','fixture_calls','entry_counts'}
            or metrics.get('call_counts')!=count*2 or metrics.get('abi_checks')!=count*2
            or metrics.get('entry_counts')!=entries or metrics.get('fixture_calls')!=sum(fixture_counts.values())
            or any(type(metrics.get(key)) is not int or metrics[key]<=0 for key in ('read_checks','write_checks'))):
        raise ValueError('Current task replacement scope or matrix differs')


def execute(index,root,context,exports,source):
    native_context=context['native']
    if (native_context.get('source_sha256')!=SOURCE or native_context.get('functions')!=FUNCTIONS
            or native_context.get('fixtures')!=FIXTURES
            or native_context.get('leaves')!={hex(GETTER):'488b41304885c07503b0ffc30fb64029c3'}
            or hashlib.sha256(source).hexdigest()!=SOURCE):
        raise ValueError('Current task replacement source/roots differ')
    native=index.extension('build-native-entry-code');image=native.Image(source)
    index.extension('quest-model-factory-static-v1').verify(index,root,context['factory_static'],exports,source)
    factory=next(function for document in exports for function in document['functions']
                 if function['address']==FUNCTIONS['factory'])
    original=index.extension('update-bindings')
    decode=index.extension('quest-action-transfer-rules-v1').decode
    def rows(api,selected_image,address):
        if address!=int(FUNCTIONS['factory'],16):return original.rows(api,selected_image,address)
        # The sealed exported instructions exclude the inline switch table. Every
        # source byte, internal edge and switch target was checked above.
        selected=[]
        for row in factory['instructions']:
            at=int(row['address'],16);raw=bytes.fromhex(row['bytes'])
            parsed=decode(api,selected_image,at,len(raw))
            if len(parsed)!=1 or parsed[0]['bytes']!=row['bytes'].lower():
                raise ValueError('Replacement source-bound factory instruction differs')
            selected+=parsed
        return selected
    def extension(name):
        return SimpleNamespace(rows=rows) if name=='update-bindings' else index.extension(name)
    def selected(sha):
        if sha!=SOURCE:raise ValueError('Replacement source selection differs')
        return source
    store=SimpleNamespace(root=root,source=selected,image=lambda api,sha:image if selected(sha) else None)
    h=index.extension('quest-tutorial-state-harness-v1').make_harness(
        SimpleNamespace(extension=extension),store,native_context,exports,context['tables'])
    uc,x,base=h.uc,h.x,h.scratch
    record0,oldtask,oldctrl,data,progress0,oldtable,oldcontroltable=[base+n for n in
        (0x1000,0x3000,0x4000,0x6000,0x7000,0x9000,0xa000)]
    state={};events=[];blocks=[];cursor=[base+0x10000]
    fixture={role:int(at,16) for role,at in native_context['fixtures'].items()}
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def integer(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,value,size=8):h.write(at,int(value).to_bytes(size,'little'))
    def require(ok,reason):
        if not ok:raise ValueError('Current task replacement: '+reason)
    def allocated(at,size):return any(p<=at and at+size<=p+n for p,n in blocks)
    def allocate(machine):
        size=reg('RCX');require(size in (0x2b0,0x100,0x18),'unknown allocation size')
        if size==0x2b0 and state['case']['primary_failure']:
            events.append('primary_failure');h.finish(0);return
        at=cursor[0]+16;cursor[0]+=((size+15)//16)*16+32
        require(cursor[0]<base+0x30000,'heap budget exceeded')
        uc.mem_write(at-16,b'G'*(size+32));h.allow_write(at,size);h.write(at,b'\xcd'*size)
        blocks.append((at,size));events.append({0x2b0:'allocate_primary',0x100:'allocate_fallback',0x18:'allocate_control'}[size])
        h.finish(at)
    def zero(machine):
        at,value,size=reg('RCX'),reg('RDX'),reg('R8')
        require(value==0 and allocated(at,size),'memset bounds/value differ')
        h.write(at,bytes(size));h.finish(at)
    def delegate(machine):
        at=reg('RCX');require(allocated(at,24),'delegate bounds differ')
        h.write(at,bytes(24));h.finish(at)
    def empty_string(machine):
        at=reg('RCX');require(allocated(at,16),'string init bounds differ')
        offset=image.offset(reg('RDX')-image.pe.base)
        require(source[offset:offset+2]==bytes(2),'nonempty initializer')
        h.write(at,bytes(16));h.finish(at)
    def nested(machine):
        require(reg('RDX')==0 and allocated(reg('RCX'),8),'nested init bounds differ')
        put(reg('RCX'),0);h.finish()
    def task_data(machine):
        require(reg('RCX')==int(state['case']['key']),'task-data key differs')
        events.append('task_data');h.finish(data)
    def init_task(machine):
        at=reg('RCX');require(bytes(uc.mem_read(at+0x20,32))==state['raw'] and integer(at+0x40)==data,
            'task init precedes progress/data')
        events.append('task_init');h.finish()
    def post_task(machine):
        require(bytes(uc.mem_read(reg('RCX')+0x20,32))==state['raw'],'post init progress differs')
        events.append('task_post');h.finish()
    def bind_owner(machine):
        require(integer(reg('RDX'))==integer(state['record']+8) and integer(reg('RDX')+8)==0,'parent context differs')
        state['newtask']=reg('RCX');events.append('owner_bind');h.finish()
    def start(machine):
        require(reg('RCX')==integer(state['record']+0x30)
            and integer(state['record']+0x28,1)==state['case']['old_state'],'start receiver/state differs')
        events.append('start');h.finish()
    def advance(machine):
        require(reg('RCX')==oldtask and integer(state['record']+0x30)==oldtask,'old advance order differs')
        events.append('advance_old');h.finish()
    def destroy(machine):
        at=reg('RCX');require(integer(at+8,4)==0,'destruction before strong zero')
        if at==oldctrl:events.append('destroy_old')
        else:
            require(allocated(at,24) and integer(at+16)==0,'unexpected new controller destruction')
            events.append('destroy_null')
        h.finish()
    def free_control(machine):
        at=reg('RCX');require(integer(at+8,4)==0 and integer(at+12,4)==0 and reg('RDX')==1,'controller release differs')
        events.append('free_old' if at==oldctrl else 'free_null');h.finish()
    def enum_provider(machine):h.finish(0)
    def format_log(machine):h.write(reg('RCX'),bytes(16));h.finish(reg('RCX'))
    def log(machine):
        require(reg('RCX')==0,'diagnostic level differs')
        events.append('fallback_log');h.finish()
    def cookie(machine):
        require(reg('RCX')==int.from_bytes(bytes.fromhex(context['cookie_bytes']),'little'),'cookie differs')
        events.append('cookie');h.finish()
    callbacks=dict(allocate=allocate,zero=zero,delegate=delegate,empty_string=empty_string,nested=nested,
        task_data=task_data,init_task=init_task,post_task=post_task,bind_owner=bind_owner,
        start_success=start,start_fallback=start,destroy=destroy,free_control=free_control,
        enum_provider=enum_provider,format_log=format_log,wrap_log=format_log,log=log,cookie=cookie,advance=advance)
    require(set(callbacks)==set(fixture),'fixture roles differ')
    for role,address in fixture.items():h.add_fixture(address,callbacks[role])
    results=[]
    for number,case in enumerate(cases()):
        record=record0+case['alignment'];progress=progress0+case['alignment']
        h.reset_regions();blocks.clear();cursor[0]=base+0x10000;events.clear()
        regions=((record,0x50),(oldtask,0x60),(oldctrl,24),(data,16),(progress,32),(oldtable,0x40),(oldcontroltable,16))
        for at,size in regions:
            uc.mem_write(at-16,b'G'*(size+32));h.allow_read(at,size)
        h.allow_write(record+0x28,1);h.allow_write(record+0x30,16);h.allow_write(oldctrl+8,8)
        raw=bytearray((number+i*13)&255 for i in range(32));struct.pack_into('<Q',raw,0,int(case['key']))
        raw[8],raw[9]=6,case['index'];raw=bytes(raw)
        uc.mem_write(progress,raw);uc.mem_write(record+8,struct.pack('<QQ',12345,0))
        uc.mem_write(record+0x28,bytes([case['old_state']]))
        existing=case['mode']!='empty'
        uc.mem_write(record+0x30,struct.pack('<QQ',oldtask if existing else 0,oldctrl if existing else 0))
        uc.mem_write(oldtask,struct.pack('<Q',oldtable))
        oldkey=(int(case['key'])+(-1 if case['mode']=='previous' else 1))&MASK
        uc.mem_write(oldtask+0x20,struct.pack('<Q',oldkey))
        uc.mem_write(oldtable,bytes(0x40));uc.mem_write(oldtable+0x38,struct.pack('<Q',fixture['advance']))
        uc.mem_write(oldcontroltable,struct.pack('<QQ',fixture['destroy'],fixture['free_control']))
        uc.mem_write(oldctrl,struct.pack('<QIIQ',oldcontroltable,case['strong'],case['weak'],oldtask))
        uc.mem_write(data,struct.pack('<QQ',int(case['key']),0))
        before={at:bytes(uc.mem_read(at-16,size+32)) for at,size in regions}
        state.clear();state.update(case=case,record=record,raw=raw,newtask=None)
        h.call(int(FUNCTIONS['state'],16),record,rdx=case['state'],r8=progress,budget=30000)
        task,control=struct.unpack('<QQ',uc.mem_read(record+0x30,16));want=expected(case)
        require(state['newtask']==task and allocated(task,0x100) and allocated(control,24),'final task ownership differs')
        require(integer(control+8,4)==integer(control+12,4)==1 and integer(control+16)==task,'new control counters/pointer differ')
        require(integer(task)==int(want['final_table'],16),'new task type differs')
        if case['primary_failure']:
            require(integer(task+0x20)==0 and integer(task+0x28,2)==0xff1f,'fallback progress differs')
        else:require(bytes(uc.mem_read(task+0x20,32))==raw,'created progress differs')
        require(events==want['events'],'event/lifecycle order differs')
        for at,size in regions:
            expected_bytes=bytearray(before[at])
            if at==record:
                expected_bytes[16+0x28]=case['state'];struct.pack_into('<QQ',expected_bytes,16+0x30,task,control)
            elif at==oldctrl and existing:struct.pack_into('<II',expected_bytes,16+8,*want['old_control'])
            require(bytes(uc.mem_read(at-16,size+32))==bytes(expected_bytes),'immutable input/padding/guard differs')
        for at,size in blocks:
            require(bytes(uc.mem_read(at-16,16))==b'G'*16 and bytes(uc.mem_read(at+size,16))==b'G'*16,'heap guard differs')
        require(h.call(GETTER,record)&255==want['final_index'],'created sender index differs')
        results.append(want)
    result=dict(FLAGS,cases=results,metrics=h.validate());validate(result)
    return result
