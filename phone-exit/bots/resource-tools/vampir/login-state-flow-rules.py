"""Source-bound composition of dispatch, post-state and continuation contracts."""
import copy
import hashlib
import json
from pathlib import Path
import re
from importlib.util import module_from_spec,spec_from_file_location

HERE=Path(__file__).resolve().parent
FAMILY='login-state-flow'
CURRENT='login-state-flow-v1'
REFERENCE='reference-login-state-flow'
META={'schema','source','source_sha256','family','format','layout','exports','transfer_proof','release_id','provenance'}
INHERITED={'bindings','globals','source_initial','tls_index_span','literals','cleanup_vtables','helpers',
    'packet_bytes','packet_allocation_bytes','owner_bytes','node_bytes','framing_minimum'}
SIZES=dict(continuation_bytes=1024,post_state_service_bytes=768,post_state_actor_bytes=832,post_state_class_bytes=64)
STATE={'post_wrapper','post_target','post_getter','continuation_constructor','continuation_reset','continuation_getter',
    'continuation_table','continuation_base_table'}
WIDTHS=dict(continuation_singleton=8,continuation_flag=1,post_state_service=8,post_state_chunks=8,post_state_count=4)
SHAPES={'post_state.wrapper':(30,100),'post_state.target':(103,386),
    'continuation.constructor':(142,983),'continuation.reset':(213,829)}
FIELDS=INHERITED|set(SIZES)|{'functions','leaves','call_sites','state_bindings','virtual_globals','dispatch_context',
    'post_state_context','continuation_context','verify_whole_exports'}


def load(name):
    s=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'));v=module_from_spec(s);s.loader.exec_module(v);return v


def tools():return {str(HERE/'login-state-flow-rules.py'):hashlib.sha256((HERE/'login-state-flow-rules.py').read_bytes()).hexdigest()}
def address(value):return load('login-dispatch-rules').address(value)
def pointer(value):return load('login-dispatch-rules').pointer(value)


def functional(c):
    if not isinstance(c,dict):raise ValueError('State-flow context must be an object')
    objects=('functions','leaves','call_sites','state_bindings','virtual_globals',*INHERITED-set(('packet_bytes','packet_allocation_bytes','owner_bytes','node_bytes','framing_minimum')))
    if any(not isinstance(c.get(k),dict) for k in objects):raise ValueError('State-flow context object field differs')
    if (set(c)-META!=FIELDS or type(c.get('schema'))is not int or c['schema']!=1 or c.get('family')!=FAMILY
            or c.get('format') not in (CURRENT,REFERENCE) or not isinstance(c.get('source'),str) or not c['source']
            or not isinstance(c.get('source_sha256'),str) or not re.fullmatch('[0-9a-f]{64}',c['source_sha256'])
            or c.get('verify_whole_exports')is not True or set(c['state_bindings'])!=STATE
            or set(c['virtual_globals'])!=set(WIDTHS) or set(c['call_sites'])!=set(c['functions'])):
        raise ValueError('State-flow functional fields/source differ')
    for key,wanted in dict(packet_bytes=352,packet_allocation_bytes=344,owner_bytes=80,node_bytes=40,framing_minimum=5,**SIZES).items():
        if type(c.get(key))is not int or c[key]!=wanted:raise ValueError('State-flow extent/precondition differs: '+key)
    for role in ('dispatch','post_state','continuation'):pointer(c[role+'_context'])
    for value in c['state_bindings'].values():address(value)
    spans=[]
    for role,width in WIDTHS.items():
        item=c['virtual_globals'][role]
        if (not isinstance(item,dict) or set(item)!={'address','size_bytes','span'}
                or type(item['size_bytes'])is not int or item['size_bytes']!=width):raise ValueError('State-flow virtual width differs')
        at=address(item['address']);section=item['span']
        if (not isinstance(section,dict) or set(section)!={'name','rva','raw','raw_size','size'} or section['name']!='.data'
                or any(type(section[k])is not int or section[k]<0 for k in ('rva','raw','raw_size','size'))):
            raise ValueError('State-flow PE virtual section differs')
        spans.append((at,at+width))
    if any(max(a,b)<min(z,y) for i,(a,z) in enumerate(spans) for b,y in spans[:i]):raise ValueError('State-flow globals overlap')
    return {k:copy.deepcopy(v) for k,v in c.items() if k not in META}


def roots(c):
    functional(c);f=c['functions']
    child={k[9:]:v for k,v in f.items() if k.startswith('dispatch.')}
    # Reconstruct only the inherited child inventory; its complete source is checked in project().
    wanted={'dispatch.'+k for k in child}|set(SHAPES)
    if len(child)!=29 or set(f)!=wanted or len({address(v) for v in f.values()})!=33 or len(c['leaves'])!=14:
        raise ValueError('State-flow explicit 33-root/14-leaf inventory differs')
    if set(child)!={'dispatch','lookup'}|{'container.'+k for k in load('login-container-rules').FUNCTIONS}|{
            'composition.'+k for k in ('handler.gate','handler.handler','input.bool','input.buffer_constructor','input.constructor',
            'input.raw','input.std_string','input.string','input.time','input.u16','input.u32','input.u64','input.utf8_convert',
            'input.utf8_core','input.utf8_length','input.utf8_scalar','packet.constructor','packet.period_constructor',
            'packet.period_reader','packet.reader','packet.time_constructor','packet.time_reader')}:
        raise ValueError('State-flow dispatch root roles differ')
    leaves={address(at) for at in c['leaves']}
    for raw in c['leaves'].values():
        if not isinstance(raw,str) or not re.fullmatch('(?:[0-9a-f]{2})+',raw):raise ValueError('State-flow leaf bytes differ')
    if len(leaves)!=14 or leaves&{address(v) for v in f.values()}:raise ValueError('State-flow leaf/root alias')
    for prefix,role in (('post_state.wrapper','post_wrapper'),('post_state.target','post_target'),
            ('continuation.constructor','continuation_constructor'),('continuation.reset','continuation_reset')):
        if f[prefix]!=c['state_bindings'][role]:raise ValueError('State-flow root binding differs')
    for role in ('post_getter','continuation_getter'):
        if len(bytes.fromhex(c['leaves'].get(c['state_bindings'][role],'')))!=8:raise ValueError('State-flow getter extent differs')
    return {address(v) for v in f.values()}


def virtual_span(image,at,width):
    if type(width)is not int or width not in (1,4,8):raise ValueError('State-flow virtual width is not declared')
    rva=at-image.pe.base
    found=[s for s in image.pe.sections if s['rva']+s['raw_size']<=rva and rva+width<=s['rva']+s['size']]
    if len(found)!=1 or found[0]['name']!='.data':raise ValueError('State-flow input is not zero-initialized data tail')
    try:image.offset(rva)
    except ValueError:pass
    else:raise ValueError('State-flow virtual input unexpectedly file-backed')
    return dict(address=hex(at),size_bytes=width,span=copy.deepcopy(found[0]))


def parents(root,c):
    core=load('portable-native-family')
    return tuple(core.checked(root,c[role+'_context'],'generated-native-contexts') for role in ('dispatch','post_state','continuation'))


def handler_links(rows,post_wrapper,continuation_getter):
    dp=load('login-dispatch-rules');at=rows[0]['address'];by_offset={r['address']-at:r for r in rows}
    if (dp.direct(rows,0x3be)!=post_wrapper or dp.direct(rows,0x3c3)!=continuation_getter
            or by_offset.get(0x3c8,{}).get('bytes')!='488bc8' or by_offset.get(0x3cb,{}).get('bytes')!='488b10'
            or by_offset.get(0x3ce,{}).get('operands')!='qword ptr [rdx + 0x28]'):
        raise ValueError('State-flow handler post/getter/virtual-reset linkage differs')


def project(root,native,bindings,image,dispatch,post,continuation,dispatch_pointer,post_state_pointer,continuation_pointer,*,format=CURRENT):
    children=(dispatch,post,continuation)
    if (tuple(c.get('family') for c in children)!=('login-dispatch','login-post-state','login-continuation')
            or any(not c.get('transfer_proof') for c in children)
            or len({c['source_sha256'] for c in children})!=1 or len({str(Path(c['source']).resolve()) for c in children})!=1):
        raise ValueError('State-flow needs three independent proved children for one source')
    dp,ps,co=load('login-dispatch-rules'),load('post-state-transfer-rules'),load('login-handler-transfer-rules')
    dp.validate_static(root,native,bindings,image,dispatch);ps.roots(post);co.roots('login-continuation',continuation)
    functions={'dispatch.'+k:v for k,v in dispatch['functions'].items()}
    functions.update({'post_state.'+k:v for k,v in post['functions'].items()});functions.update({'continuation.'+k:v for k,v in continuation['functions'].items()})
    rows={role:bindings.rows(native,image,address(functions[role])) for role in SHAPES}
    for role,shape in SHAPES.items():
        rr=rows[role]
        if not rr or rr[0]['address']!=address(functions[role]) or (len(rr),sum(len(bytes.fromhex(r['bytes'])) for r in rr))!=shape:
            raise ValueError('State-flow new whole body shape differs: '+role)
    ps.check_rows(post,{k:rows['post_state.'+k] for k in ('wrapper','target')})
    if co.call_sites({k:rows['continuation.'+k] for k in ('constructor','reset')})!=continuation['call_sites']:
        raise ValueError('State-flow continuation call-site source differs')
    for anchor in continuation['anchors']:
        if dp.data(image,address(anchor['address']),len(bytes.fromhex(anchor['bytes']))).hex()!=anchor['bytes']:
            raise ValueError('State-flow continuation anchor source differs')
    if int.from_bytes(dp.data(image,address(continuation['table'])+0x28,8),'little')!=address(continuation['functions']['reset']):
        raise ValueError('State-flow continuation vtable slot differs')
    handler=bindings.rows(native,image,address(dispatch['functions']['composition.handler.handler']))
    handler_links(handler,address(post['functions']['wrapper']),address(continuation['getter']))
    leaves=copy.deepcopy(dispatch['leaves'])
    for child in (post,continuation):
        for at,raw in child['leaves'].items():
            if at in leaves and leaves[at]!=raw:raise ValueError('State-flow leaf conflict')
            if dp.data(image,address(at),len(bytes.fromhex(raw))).hex()!=raw:raise ValueError('State-flow leaf source differs')
            leaves[at]=raw
    state=dict(post_wrapper=post['functions']['wrapper'],post_target=post['functions']['target'],post_getter=post['service_getter'],
        continuation_constructor=continuation['functions']['constructor'],continuation_reset=continuation['functions']['reset'],
        continuation_getter=continuation['getter'],continuation_table=continuation['table'],continuation_base_table=continuation['base_table'])
    globals_=dict(continuation_singleton=continuation['singleton'],continuation_flag=continuation['flag'],post_state_service=post['globals']['service'],
        post_state_chunks=post['globals']['chunks'],post_state_count=post['globals']['count'])
    c=dict(schema=1,family=FAMILY,format=format,source=dispatch['source'],source_sha256=dispatch['source_sha256'],functions=functions,
        leaves=leaves,call_sites={'dispatch.'+k:copy.deepcopy(v) for k,v in dispatch['call_sites'].items()},state_bindings=state,
        virtual_globals={k:virtual_span(image,address(v),WIDTHS[k]) for k,v in globals_.items()},dispatch_context=copy.deepcopy(dispatch_pointer),
        post_state_context=copy.deepcopy(post_state_pointer),continuation_context=copy.deepcopy(continuation_pointer),verify_whole_exports=True,**SIZES,
        **{k:copy.deepcopy(dispatch[k]) for k in INHERITED})
    c['call_sites'].update({k:dp.calls(v) for k,v in rows.items()});roots(c);return c,rows


def validate_static(root,native,bindings,image,c):
    roots(c);children=parents(root,c)
    candidate,rows=project(root,native,bindings,image,*children,c['dispatch_context'],c['post_state_context'],c['continuation_context'],format=c['format'])
    if (candidate['source_sha256']!=c['source_sha256'] or Path(candidate['source']).resolve()!=Path(c['source']).resolve()
            or functional(candidate)!=functional(c)):raise ValueError('State-flow source projection differs')
    return rows


def transfer(root,native,bindings,before,after,baseline,mapping,dispatch,post,continuation,*,dispatch_pointer,post_state_pointer,continuation_pointer):
    old=validate_static(root,native,bindings,before,baseline)
    c,new=project(root,native,bindings,after,dispatch,post,continuation,dispatch_pointer,post_state_pointer,continuation_pointer)
    common=load('update-native-archive-wire');pair=load('login-dispatch-rules').pair_declared_leaf
    for role in SHAPES:pair(native,old[role],new[role],roots(baseline),mapping)
    for role,value in baseline['functions'].items():common.add_link(mapping,address(value),address(c['functions'][role]))
    for role,value in baseline['state_bindings'].items():common.add_link(mapping,address(value),address(c['state_bindings'][role]))
    decoder=load('login-handler-transfer-rules').decode
    for role in ('post_getter','continuation_getter'):
        pair(native,decoder(native,before,address(baseline['state_bindings'][role]),8),decoder(native,after,address(c['state_bindings'][role]),8),set(),mapping)
    for role,width in WIDTHS.items():
        a,b=baseline['virtual_globals'][role],c['virtual_globals'][role]
        common.add_link(mapping,address(a['address']),address(b['address']))
        if a['size_bytes']!=b['size_bytes'] or a['span']['name']!=b['span']['name']:raise ValueError('State-flow provider storage changed')
    return c,dict(method='native_dispatch_post_state_continuation_composition',new_whole_shapes={k:list(v) for k,v in SHAPES.items()},
        providers='Ambient post-state services and captured continuation helper effects only; singleton is published by native constructor',
        packet_reseeded=False,decoded_strings_reseeded=False,session_executed=False)


def export_coverage(root,c,native,bindings,image):
    rows=validate_static(root,native,bindings,image,c);expected={address(c['functions'][k]):v for k,v in rows.items()};seen=set()
    for run,sha in c.get('exports',{}).items():
        if Path(run).name!=run or not run.startswith('run-'):raise ValueError('State-flow export name differs')
        p=Path(root)/'ghidra/request-exports'/c['source_sha256']/run/'details.json';raw=p.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('State-flow export changed')
        report=json.loads(raw)
        if report.get('new_source_sha256',report.get('source_sha256'))!=c['source_sha256']:raise ValueError('State-flow export source differs')
        for fn in report['functions']:
            at=address(fn['address'])
            if at not in expected:continue
            if any(fn.get(k)is not True for k in ('decompilation_completed','block_coverage_complete','direct_flow_coverage_complete')):
                raise ValueError('State-flow export whole coverage incomplete')
            actual=[(address(r['address']),r['bytes'].lower()) for r in fn['instructions']]
            wanted=[(r['address'],r['bytes'].lower()) for r in expected[at]]
            if len(actual)!=len(set(a for a,_ in actual)) or sorted(actual)!=sorted(wanted):raise ValueError('State-flow export instructions differ')
            load('audit-launcher-shape-11318').normalize_function(native,image,fn);seen.add(at)
    if seen!=set(expected):raise ValueError('State-flow exports lack four whole roots')
    dispatch,_,_=parents(root,c);load('login-dispatch-rules').export_coverage(root,dispatch,native,bindings,image)
