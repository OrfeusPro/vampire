"""Typed source closure for the bounded publisher/prepare/backend/Login wire path."""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
from importlib.util import module_from_spec, spec_from_file_location

HERE=Path(__file__).resolve().parent
FAMILY='login-backend-wire'
CURRENT='login-backend-wire-v1'
REFERENCE='reference-login-backend-wire'
META={'schema','source','source_sha256','family','format','layout','exports','transfer_proof','release_id','provenance'}
SHAPES={'publisher':(43,214),'backend':(120,488),'wire.append':(19,69),'wire.cleanup':(37,133)}
EXTENTS=dict(packet_bytes=320,session_bytes=160,service_bytes=240,backend_bytes=784,archive_bytes=64)
SERVICE={'helper','initial_table','primary_table','secondary_table','object_bytes'}
BACKEND={'state_getter','debug_first','debug_second','fallback','checksum_init','checksum','transform','transport',
    'packet_id_getter','get_buffer','cleanup_wrapper','cleanup_base','cleanup_final','globals'}
INPUTS={'service_global','gate','diagnostic_pointer','archive_flags','archive_table','service_initial_table',
    'service_primary_table','service_secondary_table','cleanup_wrapper_table','cleanup_table','cleanup_base_table','cleanup_final_table'}
FIELDS=set(EXTENTS)|{'functions','leaves','tails','helpers','call_sites','handoff_context','wire_context','sender',
    'service','backend','source_inputs','verify_whole_exports'}
WIRE_FUNCTIONS={'wire.'+k for k in ('length','convert','string-writer','login-writer')}|{
    'wire.archive.'+k for k in ('base-constructor','constructor','raw','string','u8','u16','u32','u64','bool')}


def load(name):
    s=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'));m=module_from_spec(s);s.loader.exec_module(m);return m


def tools():
    names=('login-backend-wire-rules.py','login-backend-wire-source.py','login-dispatch-rules.py',
        'login-handler-transfer-rules.py','login-state-flow-rules.py','knowledge-index.py','knowledge-context.py')
    return {str(HERE/n):hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in names}


def address(v):return load('login-dispatch-rules').address(v)
def data(image,at,size):return load('login-dispatch-rules').data(image,at,size)
def pointer(v):return load('login-dispatch-rules').pointer(v)
def calls(rows):return load('login-dispatch-rules').calls(rows)
def decode(native,image,at,size):return load('login-handler-transfer-rules').decode(native,image,at,size)
def rip(rows,offset):return load('login-dispatch-rules').rip(rows,offset)
def direct(rows,offset):return load('login-dispatch-rules').direct(rows,offset)


def functional(c):
    objects=('functions','leaves','tails','helpers','call_sites','sender','service','backend','source_inputs')
    if not isinstance(c,dict) or any(not isinstance(c.get(k),dict) for k in objects):raise ValueError('Backend context object fields differ')
    if (set(c)-META!=FIELDS or type(c.get('schema'))is not int or c['schema']!=1 or c.get('family')!=FAMILY
            or c.get('format') not in (CURRENT,REFERENCE) or not isinstance(c.get('source'),str) or not c['source']
            or not isinstance(c.get('source_sha256'),str) or not re.fullmatch('[0-9a-f]{64}',c['source_sha256'])
            or c.get('verify_whole_exports')is not True or set(c['service'])!=SERVICE or set(c['backend'])!=BACKEND
            or set(c['helpers'])!={'memcpy'} or set(c['call_sites'])!=set(c['functions']) or set(c['source_inputs'])!=INPUTS):
        raise ValueError('Backend typed fields/source/scope differ')
    for role,size in EXTENTS.items():
        if type(c.get(role))is not int or c[role]!=size:raise ValueError('Backend extent differs: '+role)
    if type(c['service']['object_bytes'])is not int or c['service']['object_bytes']!=240:raise ValueError('Backend publisher object extent differs')
    for key in ('handoff_context','wire_context'):pointer(c[key])
    for key in SERVICE-{'object_bytes'}:address(c['service'][key])
    for key in BACKEND-{'globals'}:address(c['backend'][key])
    g=c['backend']['globals']
    if not isinstance(g,dict) or set(g)!={'gate','diagnostic_pointer'}:raise ValueError('Backend ambient globals differ')
    for v in g.values():address(v)
    return {k:copy.deepcopy(v) for k,v in c.items() if k not in META}


def roots(c):
    functional(c)
    handoff=load('login-send-handoff-rules')
    if set(c['functions'])!=handoff.FUNCTIONS|WIRE_FUNCTIONS|set(SHAPES):raise ValueError('Backend whole root roles differ')
    whole={address(v) for v in c['functions'].values()};leaves={address(a) for a in c['leaves']};tails={address(a) for a in c['tails']}
    if (len(whole),len(leaves),len(tails))!=(29,13,3) or whole&leaves or whole&tails or leaves&tails:
        raise ValueError('Backend exact29whole/13returning/3tail inventory differs')
    for raw in (*c['leaves'].values(),*c['tails'].values()):
        if not isinstance(raw,str) or not re.fullmatch('(?:[0-9a-f]{2})+',raw):raise ValueError('Backend fragment bytes differ')
    b=c['backend']
    for role,size in (('packet_id_getter',6),('get_buffer',14),('cleanup_final',11)):
        if len(bytes.fromhex(c['leaves'].get(b[role],'')))!=size:raise ValueError('Backend explicit returning fragment differs: '+role)
    if c['leaves'][b['packet_id_getter']]!='b803000000c3':raise ValueError('Backend request ID differs from3')
    primary=c['source_inputs']['service_primary_table'];raw=bytes.fromhex(primary.get('bytes',''))
    if len(raw)!=80 or set(c['tails'])!={b['cleanup_wrapper'],b['cleanup_base'],hex(int.from_bytes(raw[56:64],'little'))}:
        raise ValueError('Backend tail roles differ')
    if (set(c['sender'])!=handoff.SENDER_FIELDS or c['sender']['virtual_slot']!=56
            or type(c['sender']['virtual_slot'])is not int or c['sender']['fifth_argument_bits']!=0
            or type(c['sender']['fifth_argument_bits'])is not int or c['sender']['address']!=c['functions']['sender']):
        raise ValueError('Backend inherited sender ABI differs')
    excluded={address(c['sender'][k]) for k in ('pending_insert','delegate_add')}|{address(c['service']['helper'])}|{
        address(b[k]) for k in ('state_getter','debug_first','debug_second','fallback','checksum_init','checksum','transform','transport')}
    if excluded&(whole|leaves|tails):raise ValueError('Backend fixture aliases native entry/leaf/tail')
    return whole


def parents(root,c):
    core=load('portable-native-family')
    return tuple(core.checked(root,c[role+'_context'],'generated-native-contexts') for role in ('handoff','wire'))


def at_rows(rows,offset):
    return next((r for r in rows if r['address']==rows[0]['address']+offset),{})


def exact(rows,offset,raw):
    if at_rows(rows,offset).get('bytes')!=raw:raise ValueError('Backend source ABI/layout instruction differs: '+hex(offset))


def table(image,at,size):return dict(address=hex(at),bytes=data(image,at,size).hex())


def terminal(native,image,at,size,target,kind):
    raw=data(image,at,size)
    if kind=='service':
        if size!=9 or raw[:5]!=bytes.fromhex('488b4910e9'):raise ValueError('Backend service thunk receiver adjustment differs')
    else:
        if size!=15 or raw[:3]!=bytes.fromhex('488d05') or raw[7:11]!=bytes.fromhex('488901e9'):
            raise ValueError('Backend cleanup tail opcode layout differs')
    actual=at+size+struct.unpack_from('<i',raw,size-4)[0]
    if actual!=target:raise ValueError('Backend source terminal tail differs')
    load('login-backend-wire-source').fragment(native,image,at,raw.hex(),tail_target=target)
    return raw.hex()


def project(root,native,bindings,image,handoff,wire,handoff_pointer,wire_pointer,new_bindings,*,format=CURRENT):
    if (handoff.get('family')!='login-send-handoff' or wire.get('family')!='archive-wire'
            or not handoff.get('transfer_proof') or not wire.get('transfer_proof')
            or handoff['source_sha256']!=wire['source_sha256'] or Path(handoff['source']).resolve()!=Path(wire['source']).resolve()
            or handoff['wire_context']!=wire_pointer or set(new_bindings)!=set(SHAPES)):
        raise ValueError('Backend needs same-source proved handoff and its exact wire context')
    pointer(handoff_pointer);pointer(wire_pointer);load('login-send-handoff-rules').roots(handoff)
    load('login-backend-wire-oracle').validate_schema(wire['packets']['game-login'])
    functions=dict(handoff['functions'])
    functions.update({'wire.'+k:v for k,v in wire['bindings'].items() if k in ('length','convert','string-writer')})
    functions.update({'wire.archive.'+k:v for k,v in wire['archive'].items() if k not in ('table','growth')})
    functions.update({'wire.login-writer':wire['packets']['game-login']['writer'],**new_bindings})
    rows={k:bindings.rows(native,image,address(at)) for k,at in functions.items()}
    for role,shape in SHAPES.items():
        rr=rows[role]
        if (len(rr),sum(len(bytes.fromhex(r['bytes'])) for r in rr))!=shape:raise ValueError('Backend whole source shape differs: '+role)
    p,b,ap,cl=(rows[k] for k in ('publisher','backend','wire.append','wire.cleanup'))
    if set(calls(p))!={hex(p[0]['address']+0x22)}:raise ValueError('Backend publisher helper closure differs')
    if rip(p,0x17)!=address(handoff['sender']['service_global']):raise ValueError('Backend native publisher/sender singleton differs')
    service=dict(helper=hex(direct(p,0x22)),initial_table=hex(rip(p,0xa)),primary_table=hex(rip(p,0x2c)),
        secondary_table=hex(rip(p,0x36)),object_bytes=240)
    for offset,raw in ((0x1e,'4883c108'),(0x3d,'48894708'),(0x41,'33c0'),(0x43,'48894710')):
        exact(p,offset,raw)
    bc={0x28:'state_getter',0x53:'debug_first',0x5c:'debug_second',0xe4:'checksum_init',0x12c:'checksum',
        0x173:'transform',0x18d:'transport',0x1cd:'fallback',0x11d:'get_buffer',0x199:'cleanup_wrapper'}
    backend={name:hex(direct(b,offset)) for offset,name in bc.items()}
    wanted_direct=set(bc)|{0x93,0xf3,0x106,0x141,0x151,0x160,0x17f,0x1a2}
    if {r['address']-b[0]['address'] for r in b if r['call'] and r['direct_target']is not None}!=wanted_direct:
        raise ValueError('Backend direct provider closure differs')
    if (any(direct(b,o)!=address(wire['archive'][name]) for o,name in ((0x93,'constructor'),(0xf3,'constructor'),(0x106,'raw')))
            or direct(b,0x141)!=address(new_bindings['wire.append'])
            or any(direct(b,o)!=address(backend['get_buffer']) for o in (0x151,0x160,0x17f))
            or direct(b,0x1a2)!=address(backend['cleanup_wrapper'])):
        raise ValueError('Backend archive source call closure differs')
    indirect={r['address']-b[0]['address']:r['operands'] for r in b if r['call'] and r['direct_target']is None}
    if indirect!={0x7a:'qword ptr [rax + 0x28]',0x83:'qword ptr [rax + 0x28]',0xa3:'qword ptr [rax + 0xd8]',
            0xc4:'qword ptr [rax + 0xd0]',0xd4:'qword ptr [rax + 0x10]',0x137:'rdi'}:
        raise ValueError('Backend virtual writer/archive ABI closure differs')
    for offset,raw in ((0x36,'4180bea502000000'),(0xa9,'410fb79640020000'),(0xb8,'6641898640020000'),
            (0x146,'498bb648020000'),(0x1b4,'4180be0003000001'),(0x1be,'4180bea502000000')):
        exact(b,offset,raw)
    # All three extra archive aliases are semantic dependencies in this scope.
    arc=address(wire['archive']['table']);packet=address(wire['packets']['game-login']['table'])
    for slot,role in ((0xc0,'u32'),(0xd0,'u16'),(0xd8,'u16')):
        if int.from_bytes(data(image,arc+slot,8),'little')!=address(wire['archive'][role]):raise ValueError('Backend archive slot alias differs')
    backend['packet_id_getter']=hex(int.from_bytes(data(image,packet+0x28,8),'little'))
    if int.from_bytes(data(image,packet+0x10,8),'little')!=address(functions['wire.login-writer']):raise ValueError('Backend packet writer slot differs')
    exact(ap,0x1b,'488bb888000000');exact(ap,0x30,'488bc7');exact(ap,0x42,'48ffe0')
    if direct(ap,0x22)!=address(backend['get_buffer']):raise ValueError('Backend native append buffer getter differs')
    tail=at_rows(cl,0x79)
    if tail.get('mnemonic')!='jmp' or tail.get('direct_target')is None:raise ValueError('Backend cleanup terminal source differs')
    backend['cleanup_base']=hex(tail['direct_target'])
    base_raw=data(image,address(backend['cleanup_base']),15)
    backend['cleanup_final']=hex(address(backend['cleanup_base'])+15+struct.unpack_from('<i',base_raw,11)[0])
    backend['globals']=dict(gate=hex(rip(b,0x15)),diagnostic_pointer=hex(rip(b,0x44)))
    leaves=copy.deepcopy(handoff['leaves'])
    leaves.update({at:item['bytes'] for at,item in wire['archive_leaves'].items()})
    leaves[wire['bindings']['encoder']]=wire['encoder_leaf']['bytes']
    for role,size in (('packet_id_getter',6),('get_buffer',14),('cleanup_final',11)):
        at=address(backend[role]);raw=data(image,at,size).hex()
        load('login-backend-wire-source').fragment(native,image,at,raw);leaves[hex(at)]=raw
    if leaves[backend['get_buffer']]!='83793000750333c0c3488b4118c3':raise ValueError('Backend capacity/buffer getter layout differs')
    final=bytes.fromhex(leaves[backend['cleanup_final']])
    if final[:3]!=bytes.fromhex('488d05') or final[7:]!=bytes.fromhex('488901c3'):raise ValueError('Backend final cleanup source differs')
    service_thunk=int.from_bytes(data(image,address(service['primary_table'])+0x38,8),'little')
    tails={hex(service_thunk):terminal(native,image,service_thunk,9,address(new_bindings['backend']),'service'),
        backend['cleanup_wrapper']:terminal(native,image,address(backend['cleanup_wrapper']),15,address(new_bindings['wire.cleanup']),'cleanup'),
        backend['cleanup_base']:terminal(native,image,address(backend['cleanup_base']),15,address(backend['cleanup_final']),'cleanup')}
    flags=rip(b,0x86)
    if rip(b,0xe9)!=flags or data(image,flags,4)!=bytes.fromhex('01000000'):raise ValueError('Backend source archive flags differ')
    prepared=load('portable-native-family').checked(root,handoff['prepare_context'],'generated-native-contexts')
    if prepared['source_sha256']!=handoff['source_sha256'] or address(prepared['globals']['enum'])!=flags:
        raise ValueError('Backend archive flags and prepared enum must share the exact source global')
    source_inputs={k:load('login-state-flow-rules').virtual_span(image,address(at),width) for k,at,width in (
        ('service_global',handoff['sender']['service_global'],8),('gate',backend['globals']['gate'],1),
        ('diagnostic_pointer',backend['globals']['diagnostic_pointer'],8))}
    source_inputs.update(archive_flags=table(image,flags,4),archive_table=table(image,arc,248),
        service_initial_table=table(image,address(service['initial_table']),48),
        service_primary_table=table(image,address(service['primary_table']),80),
        service_secondary_table=table(image,address(service['secondary_table']),8),
        cleanup_table=table(image,rip(cl,0xa),8))
    for role,key in (('cleanup_wrapper','cleanup_wrapper_table'),('cleanup_base','cleanup_base_table'),('cleanup_final','cleanup_final_table')):
        rr=decode(native,image,address(backend[role]),11 if role=='cleanup_final' else 15)
        source_inputs[key]=table(image,rip(rr,0),8)
    if source_inputs['cleanup_wrapper_table']['address']!=wire['archive']['table']:raise ValueError('Backend output cleanup table differs')
    c=dict(schema=1,family=FAMILY,format=format,source=handoff['source'],source_sha256=handoff['source_sha256'],
        functions=functions,leaves=leaves,tails=tails,helpers=copy.deepcopy(handoff['helpers']),call_sites={k:calls(rr) for k,rr in rows.items()},
        handoff_context=copy.deepcopy(handoff_pointer),wire_context=copy.deepcopy(wire_pointer),sender=copy.deepcopy(handoff['sender']),
        service=service,backend=backend,source_inputs=source_inputs,verify_whole_exports=True,**EXTENTS)
    if c['helpers']!=wire['helpers']:raise ValueError('Backend shared memcpy binding differs')
    roots(c);return c,rows


def validate_static(root,native,bindings,image,c):
    roots(c);handoff,wire=parents(root,c)
    candidate,rows=project(root,native,bindings,image,handoff,wire,c['handoff_context'],c['wire_context'],
        {k:c['functions'][k] for k in SHAPES},format=c['format'])
    if functional(candidate)!=functional(c) or candidate['source_sha256']!=c['source_sha256'] or Path(candidate['source']).resolve()!=Path(c['source']).resolve():
        raise ValueError('Backend typed source projection differs')
    return rows


def pair_rows(native,before,after,mapping,*,declared_tails=(),virtual_tail=False):
    if load('update-native-contexts').signature(native,before)!=load('update-native-contexts').signature(native,after):
        raise ValueError('Backend whole instruction shape changed')
    local={r['address'] for r in before};link=load('update-native-archive-wire').add_link
    for a,b in zip(before,after):
        if a['branch'] and not a['call'] and a['direct_target'] not in local:
            explicit=a['mnemonic']=='jmp' and a['direct_target'] in declared_tails
            virtual=(virtual_tail and a is before[-1] and a['mnemonic']=='jmp' and a['operands']=='rax' and a['direct_target']is None)
            if not explicit and not virtual:raise ValueError('Backend unreviewed external branch')
        if (a['call'] or a['branch']) and a['direct_target']is None and not a['rip_references'] and a['operands']!=b['operands']:
            raise ValueError('Backend indirect source edge changed')
        link(mapping,a['address'],b['address'])
        if a['direct_target']is not None:link(mapping,a['direct_target'],b['direct_target'])
        if len(a['rip_references'])!=len(b['rip_references']):raise ValueError('Backend source data edges changed')
        for x,y in zip(a['rip_references'],b['rip_references']):link(mapping,x,y)


def transfer(root,native,bindings,before,after,baseline,mapping,handoff,wire,*,handoff_pointer,wire_pointer):
    old=validate_static(root,native,bindings,before,baseline);common=load('update-native-archive-wire')
    current={k:hex(common.unique_root(native,bindings,before,after,address(baseline['functions'][k]))) for k in SHAPES}
    c,new=project(root,native,bindings,after,handoff,wire,handoff_pointer,wire_pointer,current)
    for role in SHAPES:
        pair_rows(native,old[role],new[role],mapping,declared_tails={address(baseline['backend']['cleanup_base'])} if role=='wire.cleanup' else (),virtual_tail=role=='wire.append')
    for role,at in baseline['functions'].items():common.add_link(mapping,address(at),address(c['functions'][role]))
    for group,keys in (('service',SERVICE-{'object_bytes'}),('backend',BACKEND-{'globals'})):
        for key in keys:common.add_link(mapping,address(baseline[group][key]),address(c[group][key]))
    for role,at in baseline['backend']['globals'].items():common.add_link(mapping,address(at),address(c['backend']['globals'][role]))
    for role in ('packet_id_getter','get_buffer','cleanup_final'):
        a,b=baseline['backend'][role],c['backend'][role]
        pair_rows(native,decode(native,before,address(a),len(bytes.fromhex(baseline['leaves'][a]))),
            decode(native,after,address(b),len(bytes.fromhex(c['leaves'][b]))),mapping)
    old_tails=[baseline['backend']['cleanup_wrapper'],baseline['backend']['cleanup_base'],hex(int.from_bytes(bytes.fromhex(baseline['source_inputs']['service_primary_table']['bytes'])[56:64],'little'))]
    new_tails=[c['backend']['cleanup_wrapper'],c['backend']['cleanup_base'],hex(int.from_bytes(bytes.fromhex(c['source_inputs']['service_primary_table']['bytes'])[56:64],'little'))]
    for a,b in zip(old_tails,new_tails):
        aa=decode(native,before,address(a),len(bytes.fromhex(baseline['tails'][a])));bb=decode(native,after,address(b),len(bytes.fromhex(c['tails'][b])))
        pair_rows(native,aa,bb,mapping,declared_tails={aa[-1]['direct_target']})
    for role,item in baseline['source_inputs'].items():
        target=c['source_inputs'][role];common.add_link(mapping,address(item['address']),address(target['address']))
        if 'bytes' not in item:
            if (item['size_bytes'],item['span']['name'])!=(target['size_bytes'],target['span']['name']):raise ValueError('Backend virtual storage changed')
        elif role=='archive_flags':
            if item['bytes']!=target['bytes']:raise ValueError('Backend archive flags changed')
        else:
            a,b=bytes.fromhex(item['bytes']),bytes.fromhex(target['bytes'])
            if len(a)!=len(b) or len(a)%8:raise ValueError('Backend source table extent changed')
            av,bv=struct.unpack('<'+'Q'*(len(a)//8),a),struct.unpack('<'+'Q'*(len(b)//8),b)
            for i,(x,y) in enumerate(zip(av,bv)):
                if any((x==av[j])!=(y==bv[j]) for j in range(i)):raise ValueError('Backend source table alias topology changed')
                common.add_link(mapping,x,y)
    return c,dict(method='native_publisher_prepare_sender_backend_login_wire_cleanup',
        whole_shapes={k:list(v) for k,v in SHAPES.items()},native_checksum=False,native_transform=False,native_transport=False,
        backend_assignment='explicit ambient fixture after source publisher zeroes service+0x10',session_executed=False)


def export_coverage(root,c,native,bindings,image):
    rr=validate_static(root,native,bindings,image,c);needed={address(c['functions'][role]):rows for role,rows in rr.items()};seen=set()
    for run,sha in c.get('exports',{}).items():
        if Path(run).name!=run or not run.startswith('run-'):raise ValueError('Backend export run differs')
        p=Path(root)/'ghidra/request-exports'/c['source_sha256']/run/'details.json'
        if hashlib.sha256(p.read_bytes()).hexdigest()!=sha:raise ValueError('Backend export SHA differs')
        r=json.loads(p.read_text('utf-8'))
        if r.get('new_source_sha256',r.get('source_sha256'))!=c['source_sha256']:raise ValueError('Backend export source differs')
        for fn in r['functions']:
            at=address(fn['address'])
            if at not in needed:continue
            load('login-backend-wire-source').check_coverage(dict(functions=[fn]),at,needed[at])
            load('audit-launcher-shape-11318').normalize_function(native,image,fn);seen.add(at)
    if seen!=set(needed):raise ValueError('Backend exports lack29complete whole roots')
