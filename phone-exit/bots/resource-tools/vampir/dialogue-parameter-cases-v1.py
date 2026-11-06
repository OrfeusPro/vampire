"""Native dialogue-group parameter selection with explicit JSON/class providers."""
import struct
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

CALLBACK=0x2803e000
UNSET_GROUP=int.from_bytes(b'G'*8,'little')


def validate(value):
    if (value.get('scope')!='parameter_group_only' or value.get('json_and_class_providers')!='fixtures'
            or any(value.get(key) is not False for key in ('non_null_shared_control_executed','active_task_verified',
                'dialogue_started','skip_behavior_verified','network_used'))
            or value.get('cases')!=[expected(case) for case in cases()]
            or value.get('metrics',{}).get('call_counts')!=26 or value['metrics']['abi_checks']!=26):
        raise ValueError('Dialogue native parameter proof scope differs')


def cached_execute(index,owner,root,context,export,source,runtime):
    """Resource text changes do not rerun an unchanged parameter matrix."""
    here=Path(__file__).resolve().parent
    files={str(path):owner.digest(path) for path in (Path(__file__).resolve(),
        *(here/(name+'.py') for name in ('quest-tutorial-state-harness-v1','update-bindings',
            'build-native-entry-code','login-input-transfer-rules','extract-native-enums','audit-client-release',
            'research-workflow')))}
    definition=dict(source_sha256=context['source_sha256'],export=context['export'],
        context={k:context[k] for k in ('parser','literal_roles','literals','native')},files=files,runtime_inputs=runtime)
    workflow=index.extension('research-workflow');recipe='dialogue-parameter-native-v1'
    key=hashlib.sha256(workflow.canonical(definition)).hexdigest()
    cache=root/'knowledge'/(recipe+'-cache')/(key+'.json')
    if cache.is_file():
        pointer=json.loads(cache.read_bytes());path=Path(pointer['path']).resolve()
        if (not path.is_relative_to(root/'code-clues'/recipe) or path.name!='manifest.json'
                or path.parent.name!=pointer['sha256']):
            raise ValueError('Dialogue native cache location differs')
        with path.open('rb') as stream:raw=stream.read(32*1024*1024+1)
        if len(raw)>32*1024*1024 or owner.remember(path,raw)!=pointer['sha256']:
            raise ValueError('Dialogue native cache identity differs')
        proof=json.loads(raw)
        if proof.get('schema')!=1 or proof.get('recipe')!=recipe or proof.get('inputs')!=definition:
            raise ValueError('Dialogue native cache inputs differ')
        validate(proof['result']);return proof['result'],pointer,None
    result=execute(index,root,context,export,source);validate(result)
    proof=dict(schema=1,recipe=recipe,inputs=definition,result=result)
    path=index.extension('audit-client-release').save_snapshot(root/'code-clues'/recipe,proof)
    pointer=dict(path=str(path),sha256=owner.digest(path))
    # Caller publishes the cache pointer only after the shared final SHA barrier.
    return result,pointer,dict(path=str(cache),pointer=pointer)


def cases():
    values=[]
    for alignment in (0,3):
        for group in (0,11012002,0xffffffffffffffff):
            values.append(dict(mode='direct',alignment=alignment,direct=str(group),entries=[],provider='present',class_id=1))
        for mode,entries,provider,kind in (
            ('missing',[], 'present',1),('empty',[], 'present',1),
            ('match',[(1,11012002)],'present',1),('other',[(2,11012002)],'present',1),
            ('last_match',[(1,11),(2,22),(1,33)],'present',1),
            ('missing_group',[(1,None)],'present',1),
            ('missing_then_match',[(1,None),(1,33)],'present',1),
            ('null_provider',[(0,44),(1,55)],'null_provider',1),
            ('null_handle',[(0,44),(1,55)],'null_handle',1),
            ('signed_class',[(0xffffffff,77),(1,88)],'present',0xffffffff)):
            values.append(dict(mode=mode,alignment=alignment,direct=None,
                entries=[dict(class_id=k,group=None if g is None else str(g)) for k,g in entries],provider=provider,class_id=kind))
    return values


def expected(case):
    group=UNSET_GROUP
    events=['direct']
    if case['direct'] is not None:
        group=int(case['direct'])
    else:
        events.append('branches')
        for row in case['entries']:
            events+=['json_value','class_key','provider']
            if case['provider']!='null_provider':
                events+=['provider','handle']
                if case['provider']!='null_handle':
                    events.append('class_id')
            active_class=case['class_id'] if case['provider']=='present' else 0
            if row['class_id']==active_class:
                events+=['json_value','branch_group']
                if row['group'] is not None:
                    group=int(row['group'])
        events.append('cleanup')
        if case['entries']:
            events.append('free')
    return dict(case=case,group=str(group),events=events)


def execute(index,root,context,export,source):
    native=index.extension('build-native-entry-code')
    image=native.Image(source)
    def selected(sha):
        if sha!=context['source_sha256']:raise ValueError('Dialogue source differs')
        return source
    def selected_image(api,sha):
        selected(sha)
        return image
    store=SimpleNamespace(root=root,source=selected,image=selected_image)
    h=index.extension('quest-tutorial-state-harness-v1').make_harness(
        index,store,context['native'],[export],context['literals'])
    uc,x=h.uc,h.x
    base=h.scratch
    pointer,output,json_root,array,objects,table,provider,actor=[base+n for n in
        (0x1000,0x2000,0x3000,0x4000,0x5000,0x6000,0x7000,0x8000)]
    fixture={k:int(v,16) for k,v in context['native']['fixtures'].items()}
    selected_case={};events=[]
    literal={k:int(v,16) for k,v in context['literal_roles'].items()}
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def require(ok,why):
        if not ok:raise ValueError('Dialogue parameter: '+why)
    def entry(address):
        i=(address-objects)//32
        require(address==objects+32*i and 0<=i<len(selected_case['entries']),'unknown branch JSON object')
        return selected_case['entries'][i]
    def group(machine):
        require(reg('RDX')==literal['group'] and reg('R8')==output+selected_case['alignment']+0x20,'group key or output differs')
        if reg('RCX')==json_root:
            value=selected_case['direct'];events.append('direct')
        else:
            value=entry(reg('RCX'))['group'];events.append('branch_group')
        if value is not None:h.write(reg('R8'),struct.pack('<Q',int(value)))
        h.finish(0 if value is None else 1)
    def branches(machine):
        require(reg('RCX')==json_root and reg('RDX')==literal['branches'],'class branch key differs')
        events.append('branches')
        present=selected_case['mode']!='missing'
        count=len(selected_case['entries'])
        h.write(reg('R8'),struct.pack('<QII',array if count else 0,count,count))
        h.finish(int(present))
    def json_value(machine):
        entry(reg('RCX'));events.append('json_value');h.finish(reg('RCX'))
    def class_key(machine):
        require(reg('RDX')==literal['class'],'class property differs')
        h.write(reg('R8'),struct.pack('<I',entry(reg('RCX'))['class_id']))
        events.append('class_key');h.finish(1)
    def class_provider(machine):
        events.append('provider')
        h.finish(0 if selected_case['provider']=='null_provider' else provider)
    def handle(machine):
        require(reg('RCX')==provider+0x28,'class handle differs')
        events.append('handle');h.finish(0 if selected_case['provider']=='null_handle' else actor)
    def class_id(machine):
        require(reg('RCX')==actor,'actor provider differs')
        events.append('class_id');h.finish(selected_case['class_id'])
    def cleanup(machine):
        count=len(selected_case['entries'])
        require(reg('RCX')==(array if count else 0) and reg('RDX')==count,'borrowed array cleanup differs')
        events.append('cleanup');h.finish()
    def free_array(machine):
        require(reg('RCX')==array,'array release differs')
        events.append('free');h.finish()
    callbacks=dict(group=group,branches=branches,class_key=class_key,provider=class_provider,
        handle=handle,class_id=class_id,cleanup=cleanup,free=free_array,json_value=json_value)
    require(set(callbacks)==set(fixture),'fixture roles differ')
    for name,address in fixture.items():h.add_fixture(address,callbacks[name])
    require(context['native']['readonly_globals']=={'0x1496731e0':'00000000'},'default class differs')
    results=[]
    for value in cases():
        selected_case.clear();selected_case.update(value);events.clear()
        at=output+value['alignment']
        h.reset_regions();h.allow_read(pointer,8);h.allow_read(array,48)
        h.allow_read(objects,96);h.allow_read(table,8);h.allow_write(at+0x20,8)
        uc.mem_write(pointer,struct.pack('<Q',at))
        uc.mem_write(output-16,b'G'*160);before=bytes(uc.mem_read(output-16,160))
        uc.mem_write(array,bytes(48));uc.mem_write(objects,bytes(96));uc.mem_write(table,struct.pack('<Q',CALLBACK))
        for i,row in enumerate(value['entries']):
            uc.mem_write(array+16*i,struct.pack('<QQ',objects+32*i,0))
            uc.mem_write(objects+32*i,struct.pack('<Q',table))
        input_before={p:bytes(uc.mem_read(p,n)) for p,n in ((pointer,8),(array,48),(objects,96),(table,8))}
        expectation=expected(value)
        h.call(int(context['parser'],16),pointer,rdx=json_root,budget=20000)
        actual=bytearray(uc.mem_read(output-16,160));wanted=bytearray(before)
        struct.pack_into('<Q',wanted,16+value['alignment']+0x20,int(expectation['group']))
        require(actual==wanted,'output/guard or missing-value preservation differs')
        require(events==expectation['events'],'provider or branch order differs')
        require(all(bytes(uc.mem_read(p,len(raw)))==raw for p,raw in input_before.items()),'input mutated')
        results.append(expectation)
    return dict(cases=results,metrics=h.validate(),
        scope='parameter_group_only',json_and_class_providers='fixtures',non_null_shared_control_executed=False,
        active_task_verified=False,dialogue_started=False,skip_behavior_verified=False,network_used=False)
