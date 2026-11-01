"""Typed source contract for Login preparation and its bounded native sender."""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
from importlib.util import module_from_spec,spec_from_file_location

HERE=Path(__file__).resolve().parent
FAMILY='login-send-handoff'
CURRENT='login-send-handoff-v1'
REFERENCE='reference-login-send-handoff'
META={'schema','source','source_sha256','family','format','layout','exports','transfer_proof','release_id','provenance'}
FIELDS={'functions','leaves','helpers','call_sites','prepare_context','wire_context','sender','source_inputs','packet_bytes','session_bytes','verify_whole_exports'}
FUNCTIONS={'prepare','constructor','sender','sdk.sdk_main_text','sdk.sdk_mode','sdk.sdk_value',
    'metadata.collector','metadata.copy','metadata.loader','metadata.move','metadata.selector','metadata.writer'}
SENDER_FIELDS={'address','callsite','service_getter','service_global','pending_insert','delegate_add','delegate_literal',
    'virtual_callsite','virtual_slot','fifth_argument_bits'}


def load(name):
    s=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'));v=module_from_spec(s);s.loader.exec_module(v);return v


def tools():
    names=('login-send-handoff-rules.py','login-dispatch-rules.py','login-handler-transfer-rules.py',
        'knowledge-index.py','knowledge-context.py')
    return {str(HERE/name):hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in names}
def address(value):return load('login-dispatch-rules').address(value)
def pointer(value):return load('login-dispatch-rules').pointer(value)
def data(image,at,size):return load('version-system-transfer-rules').image_bytes(image,at,size)
def calls(rows):return load('login-dispatch-rules').calls(rows)


def functional(c):
    if not isinstance(c,dict):raise ValueError('Handoff context must be an object')
    for k in ('functions','leaves','helpers','call_sites','sender','source_inputs'):
        if not isinstance(c.get(k),dict):raise ValueError('Handoff object field differs: '+k)
    if (set(c)-META!=FIELDS or type(c.get('schema'))is not int or c['schema']!=1 or c.get('family')!=FAMILY
            or c.get('format') not in (CURRENT,REFERENCE) or not isinstance(c.get('source'),str) or not c['source']
            or not isinstance(c.get('source_sha256'),str) or not re.fullmatch('[0-9a-f]{64}',c['source_sha256'])
            or c.get('verify_whole_exports')is not True or set(c['functions'])!=FUNCTIONS
            or set(c['call_sites'])!=FUNCTIONS or set(c['helpers'])!={'memcpy'} or set(c['sender'])!=SENDER_FIELDS
            or set(c['source_inputs'])!={'service_global','send_argument','delegate_callback'}):
        raise ValueError('Handoff source/fields/scope differ')
    for key,wanted in (('packet_bytes',320),('session_bytes',160)):
        if type(c.get(key))is not int or c[key]!=wanted:raise ValueError('Handoff layout differs: '+key)
    for role in ('prepare','wire'):pointer(c[role+'_context'])
    s=c['sender']
    for key in SENDER_FIELDS-{'virtual_slot','fifth_argument_bits'}:address(s[key])
    if type(s['virtual_slot'])is not int or s['virtual_slot']!=56 or type(s['fifth_argument_bits'])is not int or s['fifth_argument_bits']!=0:
        raise ValueError('Handoff virtual slot/fifth argument differs')
    if s['address']!=c['functions']['sender']:raise ValueError('Handoff sender binding differs')
    return {k:copy.deepcopy(v) for k,v in c.items() if k not in META}


def roots(c):
    functional(c);whole={address(v) for v in c['functions'].values()};leaves={address(at) for at in c['leaves']}
    if len(whole)!=12 or len(leaves)!=7 or len(c['leaves'])!=7 or whole&leaves:raise ValueError('Handoff explicit 12-root/7-leaf inventory differs')
    for raw in c['leaves'].values():
        if not isinstance(raw,str) or not re.fullmatch('(?:[0-9a-f]{2})+',raw):raise ValueError('Handoff leaf bytes differ')
    getter=c['sender']['service_getter'];code=bytes.fromhex(c['leaves'].get(getter,''))
    if (len(code)!=8 or code[:3]!=b'\x48\x8b\x05' or code[7:]!=b'\xc3'
            or address(getter)+7+struct.unpack_from('<i',code,3)[0]!=address(c['sender']['service_global'])):
        raise ValueError('Handoff native getter/global differs')
    if whole&{address(c['sender'][k]) for k in ('pending_insert','delegate_add','delegate_literal','service_global')}:
        raise ValueError('Handoff fixtures/data alias native roots')
    return whole


def parents(root,c):
    core=load('portable-native-family')
    return tuple(core.checked(root,c[role+'_context'],'generated-native-contexts') for role in ('prepare','wire'))


def virtual_input(image,at):
    rva=at-image.pe.base
    found=[s for s in image.pe.sections if s['rva']+s['raw_size']<=rva and rva+8<=s['rva']+s['size']]
    if len(found)!=1 or found[0]['name']!='.data':raise ValueError('Handoff service singleton is not zero-fill data')
    try:image.offset(rva)
    except ValueError:pass
    else:raise ValueError('Handoff singleton unexpectedly file-backed')
    return dict(address=hex(at),size_bytes=8,span=copy.deepcopy(found[0]))


def project(root,native,bindings,image,prepare,wire,prepare_pointer,wire_pointer,*,format=CURRENT):
    if (prepare.get('family')!='login-prepare-metadata' or wire.get('family')!='archive-wire'
            or not prepare.get('transfer_proof') or not wire.get('transfer_proof')
            or prepare['source_sha256']!=wire['source_sha256'] or Path(prepare['source']).resolve()!=Path(wire['source']).resolve()):
        raise ValueError('Handoff requires proved same-source preparation and wire schema')
    pointer(prepare_pointer);pointer(wire_pointer)
    load('update-native-login-metadata').scoped_roots('login-prepare-metadata',prepare)
    functions=dict(prepare=prepare['prepare'],constructor=prepare['constructor'])
    functions.update({'sdk.'+k:v for k,v in prepare['native_sdk']['functions'].items()})
    functions.update({'metadata.'+k:v for k,v in prepare['native_metadata']['functions'].items()})
    sender=address(prepare['fixtures']['send']);functions['sender']=hex(sender)
    rows={k:bindings.rows(native,image,address(at)) for k,at in functions.items()}
    rr=rows['sender'];dp=load('login-dispatch-rules')
    if len(rr)!=64 or sum(len(bytes.fromhex(r['bytes'])) for r in rr)!=250 or rr[0]['address']!=sender:
        raise ValueError('Handoff sender whole body differs')
    direct={r['address']-sender:r['direct_target'] for r in rr if r['call'] and r['direct_target']is not None}
    indirect=[(r['address']-sender,r['operands']) for r in rr if r['call'] and r['direct_target']is None]
    if set(direct)!={185,211,216} or indirect!=[(230,'qword ptr [r8 + 0x38]')]:raise ValueError('Handoff sender call closure differs')
    # All memory offsets and control flow are retained by whole-body transfer.
    fixed={27:'488bf2',33:'450fbfd8',118:'f30f104c2470',124:'0f57c0',132:'f30f104b30',142:'f30f114c2420',221:'488bd6',224:'488bc8',227:'4c8b00'}
    actual={r['address']-sender:r['bytes'] for r in rr}
    if any(actual.get(offset)!=raw for offset,raw in fixed.items()):raise ValueError('Handoff packet/timeout/virtual receiver source differs')
    raw=data(image,direct[216],8)
    if image.containing(direct[216])is not None or raw[:3]!=b'\x48\x8b\x05' or raw[7:]!=b'\xc3':raise ValueError('Handoff service getter is not exact returning leaf')
    singleton=direct[216]+7+struct.unpack_from('<i',raw,3)[0]
    references={r['address']-sender:r['rip_references'] for r in rr if r['rip_references']}
    if set(references)!={190} or len(references[190])!=1:raise ValueError('Handoff callback token source differs')
    callback=references[190][0]
    sites=[r for r in rows['prepare'] if r['call'] and r['direct_target']==sender]
    if len(sites)!=1:raise ValueError('Handoff needs one source prepare→sender edge')
    callsite=sites[0]['address'];by_at={r['address']:r for r in rows['prepare']}
    if by_at.get(callsite-18,{}).get('bytes')!='0f57c0' or by_at.get(callsite-6,{}).get('bytes')!='f30f11442420':
        raise ValueError('Handoff prepare fifth float argument is not zero')
    spec=wire['packets']['game-login']
    if spec['object_size']!=320 or spec['table']!=prepare['packet_table'] or int.from_bytes(data(image,address(spec['table'])+16,8),'little')!=address(spec['writer']):
        raise ValueError('Handoff prepared packet and independent Login wire schema differ')
    leaves={at:item['bytes'] for at,item in prepare['native_sdk']['leaves'].items()};leaves[hex(direct[216])]=raw.hex()
    s=dict(address=hex(sender),callsite=hex(callsite),service_getter=hex(direct[216]),service_global=hex(singleton),
        pending_insert=hex(direct[185]),delegate_add=hex(direct[211]),delegate_literal=hex(callback),
        virtual_callsite=hex(sender+230),virtual_slot=56,fifth_argument_bits=0)
    send_global=address(prepare['send_argument_global'])
    c=dict(schema=1,family=FAMILY,format=format,source=prepare['source'],source_sha256=prepare['source_sha256'],
        functions=functions,leaves=leaves,helpers=copy.deepcopy(prepare['helpers']),call_sites={k:calls(v) for k,v in rows.items()},
        prepare_context=copy.deepcopy(prepare_pointer),wire_context=copy.deepcopy(wire_pointer),sender=s,
        source_inputs=dict(service_global=virtual_input(image,singleton),send_argument=dict(address=hex(send_global),bytes=data(image,send_global,8).hex()),
            delegate_callback=dict(address=hex(callback),bytes=data(image,callback,8).hex())),
        packet_bytes=320,session_bytes=160,verify_whole_exports=True)
    roots(c);return c,rows


def validate_static(root,native,bindings,image,c):
    roots(c);p,w=parents(root,c)
    candidate,rows=project(root,native,bindings,image,p,w,c['prepare_context'],c['wire_context'],format=c['format'])
    if candidate['source_sha256']!=c['source_sha256'] or Path(candidate['source']).resolve()!=Path(c['source']).resolve() or functional(candidate)!=functional(c):
        raise ValueError('Handoff source projection differs')
    return rows


def transfer(root,native,bindings,before,after,baseline,mapping,prepare,wire,*,prepare_pointer,wire_pointer):
    old=validate_static(root,native,bindings,before,baseline)
    c,new=project(root,native,bindings,after,prepare,wire,prepare_pointer,wire_pointer)
    common=load('update-native-archive-wire');common.pair_rows(native,old['sender'],new['sender'],mapping)
    for role,at in baseline['functions'].items():common.add_link(mapping,address(at),address(c['functions'][role]))
    for role in SENDER_FIELDS-{'virtual_slot','fifth_argument_bits'}:common.add_link(mapping,address(baseline['sender'][role]),address(c['sender'][role]))
    decode=load('login-handler-transfer-rules').decode
    common.pair_rows(native,decode(native,before,address(baseline['sender']['service_getter']),8),decode(native,after,address(c['sender']['service_getter']),8),mapping)
    for role in ('send_argument','delegate_callback'):
        if baseline['source_inputs'][role]['bytes']!=c['source_inputs'][role]['bytes']:raise ValueError('Handoff typed input changed: '+role)
    return c,dict(method='native_prepare_sender_duplicate_gate_and_service_handoff',sender_instructions=64,sender_bytes=250,
        packet_reseeded=False,wire_executed=False,synthetic_service_vtable=True,map_insert_and_delegate_effects='fixtures',session_executed=False)


def export_coverage(root,c,native,bindings,image):
    rows=validate_static(root,native,bindings,image,c);needed={address(c['functions'][k]):rr for k,rr in rows.items()};seen=set()
    for run,sha in c.get('exports',{}).items():
        if Path(run).name!=run or not run.startswith('run-'):raise ValueError('Handoff export name differs')
        p=Path(root)/'ghidra/request-exports'/c['source_sha256']/run/'details.json';raw=p.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Handoff export SHA differs')
        r=json.loads(raw)
        if r.get('new_source_sha256',r.get('source_sha256'))!=c['source_sha256']:raise ValueError('Handoff export source differs')
        for fn in r['functions']:
            at=address(fn['address'])
            if at not in needed:continue
            if any(fn.get(k)is not True for k in ('decompilation_completed','block_coverage_complete','direct_flow_coverage_complete')):raise ValueError('Handoff export whole coverage incomplete')
            actual=[(address(x['address']),x['bytes'].lower()) for x in fn['instructions']]
            wanted=[(x['address'],x['bytes'].lower()) for x in needed[at]]
            if len(actual)!=len(set(a for a,_ in actual)) or sorted(actual)!=sorted(wanted):raise ValueError('Handoff export instructions differ')
            load('audit-launcher-shape-11318').normalize_function(native,image,fn);seen.add(at)
    if seen!=set(needed):raise ValueError('Handoff exports lack twelve whole roots')
