"""Portable two-root Version preparation with explicit synthetic input boundaries."""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
from importlib.util import spec_from_file_location,module_from_spec

HERE=Path(__file__).resolve().parent
ADAPTER='version-prepare-v1'
FAMILY='version-prepare'
SCOPE='bounded_native_version_prepare'
INDEX='generated-version-prepare'
PROOFS='native-version-prepare-proofs'
LAYOUT=dict(abi='win64',packet_bytes=208,owner_reset_offset=352,max_allocation=2048,
    executed_roots=2,optional_native_helpers=False)
OWN_TOOLS=('update-native-version-prepare.py','verify-version-prepare-context.py')
# Offsets are part of the reviewed shape/layout rule, not release addresses.
DATA_ROLES={118:('underscore',4),273:('text_count',4),280:('text_pointer',8),
    570:('compiled_tag_pointer',8),674:('enum',4),759:('log_descriptor',16),
    776:('log_integer',4),783:('log_address_argument',8),790:('log_float',4),803:('log_bss',8)}


def load(name):
    spec=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):return load('update-native-contexts').digest(path)
def tools():return {**load('update-native-archive-wire').tools(),**{str(HERE/n):digest(HERE/n) for n in OWN_TOOLS}}
def checked(root,item,category):return load('update-native-contexts').checked(root,item,category)
def image_bytes(image,address,size):return load('update-native-contexts').image_bytes(image,address,size)


def plain(context):return {k:copy.deepcopy(v) for k,v in context.items() if k not in ('exports','transfer_proof','release_id')}


def roots(context):
    if any(k in context for k in ('native_nm','native_system','native_combiners','native_platform','function_budget')):
        raise ValueError('Base Version prepare cannot admit optional native helpers')
    values={int(context[k],16) for k in ('prepare','constructor')}
    if len(values)!=2:raise ValueError('Version prepare root aliases constructor')
    return values


def data_input(image,address,size):
    """Only file-backed data or a completely proven PE zero-fill interval."""
    try:return dict(storage='file',bytes=image_bytes(image,address,size).hex())
    except ValueError:
        rva=address-image.pe.base
        sections=[s for s in image.pe.sections if s['rva']+s['raw_size']<=rva and rva+size<=s['rva']+s['size']]
        if len(sections)!=1:raise ValueError('Version data is outside file and PE zero-fill')
        s=sections[0]
        return dict(storage='pe-zero-fill',size=size,section=s['name'],virtual_size=s['size'],raw_size=s['raw_size'])


def typed_data(before,after,baseline,mapping):
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    rows=bindings.rows(native,before,int(baseline['prepare'],16));refs={r['address']-int(baseline['prepare'],16):r['rip_references'] for r in rows if r['rip_references']}
    if set(refs)!=set(DATA_ROLES) or any(len(v)!=1 for v in refs.values()):raise ValueError('Version prepare static data roles changed')
    result=[]
    for offset,(role,size) in DATA_ROLES.items():
        old=refs[offset][0];new=mapping[old]
        old_data,new_data=data_input(before,old,size),data_input(after,new,size)
        if role=='compiled_tag_pointer':
            if old!=int(baseline['globals']['tag_pointer'],16):raise ValueError('Version tag pointer role changed')
            old_literal=struct.unpack('<Q',bytes.fromhex(old_data['bytes']))[0]
            if old_literal!=int(baseline['compiled_tag_source']['literal'],16):raise ValueError('Version baseline tag pointer changed')
            old_raw=image_bytes(before,old_literal,33)
            if old_raw!=baseline['compiled_tag_source']['value'].encode('ascii')+b'\0':raise ValueError('Version baseline tag literal changed')
            literal=struct.unpack('<Q',bytes.fromhex(new_data['bytes']))[0];raw=image_bytes(after,literal,33)
            if not re.fullmatch(b'[0-9A-F]{32}\0',raw):raise ValueError('Version compiled tag is not an exact bounded hex literal')
            new_data.update(literal=hex(literal),value=raw[:-1].decode('ascii'))
        elif old_data!=new_data:
            raise ValueError('Version typed input changed: '+role)
        if role=='underscore' and new_data!=dict(storage='file',bytes='5f000000'):
            raise ValueError('Version combiner separator changed')
        if role=='text_count' and old!=int(baseline['globals']['text'],16)+8:raise ValueError('Version text count linkage changed')
        if role=='text_pointer' and old!=int(baseline['globals']['text'],16):raise ValueError('Version text descriptor linkage changed')
        if role=='enum' and old!=int(baseline['globals']['enum'],16):raise ValueError('Version enum linkage changed')
        result.append(dict(offset=offset,role=role,address=hex(new),input=new_data,
            scope='Synthetic emulator input' if role in ('text_count','text_pointer','enum') else 'Static literal or non-executed logging boundary'))
    return result


def fixture_boundaries(image,context):
    values={name:int(value,16) for name,value in context['fixtures'].items()};values['send']=int(context['send'],16)
    if len(values)!=len(set(values.values())) or set(values.values())&roots(context):raise ValueError('Version fixture aliases executable code or another role')
    result={}
    for role,at in values.items():
        part=image.containing(at)
        if part is None or image.roots[part][0]+image.pe.base!=at:
            if role=='log' and image_bytes(image,at,3)==b'\xc2\0\0':
                result[role]=dict(address=hex(at),scope='Reviewed empty ret-0 logger leaf; replaced fixture, not executed')
                continue
            raise ValueError('Version fixture is not a concrete unwind entry: '+role)
        result[role]=dict(address=hex(at),scope='Captured/replaced fixture; body not executed')
    return result


def transfer(native,bindings,before,after,baseline,archive):
    common=load('update-native-archive-wire');mapping={};roots(baseline)
    old_prepare,old_ctor=[int(baseline[k],16) for k in ('prepare','constructor')]
    # The large unique caller resolves its constructor by an exact call edge.
    new_prepare=common.unique_root(native,bindings,before,after,old_prepare)
    common.add_link(mapping,old_prepare,new_prepare)
    common.pair_rows(native,bindings.rows(native,before,old_prepare),bindings.rows(native,after,new_prepare),mapping)
    if old_ctor not in mapping:raise ValueError('Version constructor has no prepare call edge')
    new_ctor=mapping[old_ctor]
    common.pair_rows(native,bindings.rows(native,before,old_ctor),bindings.rows(native,after,new_ctor),mapping)
    declared={hex(r['address']):dict(target=hex(r['direct_target']) if r['direct_target'] is not None else r['operands'])
        for at in (old_prepare,old_ctor) for r in bindings.rows(native,before,at) if r['call']}
    if declared!=baseline['call_sites']:raise ValueError('Version baseline call roles changed')
    def mapped(text):
        at=int(text,16)
        if at not in mapping:raise ValueError('Version preparation undeclared address: '+text)
        return hex(mapping[at])
    ctor_refs=[r for r in bindings.rows(native,before,old_ctor) if r['rip_references']]
    if [r['address']-old_ctor for r in ctor_refs]!=[6,124,136]:raise ValueError('Version constructor data offsets changed')
    for row,expected in zip(ctor_refs,(baseline['packet_table'],baseline['globals']['tag_pointer'],baseline['globals']['enum'])):
        if row['rip_references']!=[int(expected,16)]:raise ValueError('Version constructor data role changed')
    packet=archive['packets']['game-version'];packet_table=mapped(baseline['packet_table'])
    if packet_table!=packet['table'] or struct.unpack('<Q',image_bytes(after,int(packet_table,16)+16,8))[0]!=int(packet['writer'],16):
        raise ValueError('Version constructor packet table does not match proved wire writer')
    old_wrapper=int(baseline['wrapper_table'],16);old_raw=image_bytes(before,old_wrapper,80)
    if hashlib.sha256(old_raw).hexdigest()!=baseline['wrapper_table_sha256']:raise ValueError('Version baseline wrapper table changed')
    if (struct.unpack_from('<Q',old_raw,56)[0],struct.unpack_from('<Q',old_raw,72)[0])!=(int(baseline['send'],16),old_prepare):
        raise ValueError('Version baseline wrapper slots differ')
    hits=load('align-wire-contexts-11320').packet_table_candidates(after,old_wrapper,new_prepare)
    # The shared scanner handles a +16 slot; here the reviewed slot is +72.
    hits=[at-56 for at in hits]
    if len(hits)!=1:raise ValueError('Version missing or ambiguous wrapper table')
    wrapper=hits[0];raw=image_bytes(after,wrapper,80);send=struct.unpack_from('<Q',raw,56)[0]
    common.add_link(mapping,old_wrapper,wrapper);common.add_link(mapping,int(baseline['send'],16),send)
    current=copy.deepcopy(baseline)
    for key in ('exports','release_id','transfer_proof'):current.pop(key,None)
    current.update(schema=1,family=FAMILY,source_sha256=archive['source_sha256'],source=archive['source'],layout=LAYOUT,
        prepare=hex(new_prepare),constructor=hex(new_ctor),packet_table=packet_table,wrapper_table=hex(wrapper),send=hex(send),
        wrapper_table_sha256=hashlib.sha256(raw).hexdigest(),globals={key:mapped(at) for key,at in baseline['globals'].items()},
        fixtures={key:mapped(at) for key,at in baseline['fixtures'].items()},helpers={'memcpy':archive['helpers']['memcpy']},verify_whole_exports=True)
    if mapped(baseline['helpers']['memcpy'])!=archive['helpers']['memcpy']:raise ValueError('Version prepare memcpy dependency changed')
    data=typed_data(before,after,baseline,mapping);tag=next(row['input'] for row in data if row['role']=='compiled_tag_pointer')
    current['compiled_tag_source']=dict(literal=tag['literal'],value=tag['value'])
    current['call_sites']={hex(r['address']):dict(target=hex(r['direct_target']) if r['direct_target'] is not None else r['operands'])
        for at in (new_prepare,new_ctor) for r in bindings.rows(native,after,at) if r['call']}
    fixture_boundaries(before,baseline);boundaries=fixture_boundaries(after,current)
    return current,dict(mapping={hex(a):hex(b) for a,b in sorted(mapping.items())},typed_inputs=data,fixtures=boundaries,
        packet_wire_dependency=dict(table=packet_table,writer=packet['writer']),
        wrapper=dict(address=hex(wrapper),sha256=current['wrapper_table_sha256'],used_slots=[56,72],
            excluded_slots=[i for i in range(0,80,8) if i not in (56,72)]))


def export_coverage(root,context,native,bindings,image):
    needed=roots(context);available=set()
    for run,expected in context.get('exports',{}).items():
        if Path(run).name!=run or not run.startswith('run-'):raise ValueError('Invalid Version prepare export')
        p=Path(root)/'ghidra/request-exports'/context['source_sha256']/run/'details.json'
        if digest(p)!=expected:raise ValueError('Version prepare export changed')
        report=json.loads(p.read_text('utf-8'))
        if report.get('new_source_sha256',report.get('source_sha256'))!=context['source_sha256']:raise ValueError('Version prepare export source differs')
        for fn in report['functions']:
            at=int(fn['address'],16)
            if at not in needed or fn.get('decompilation_completed') is not True:continue
            wanted={(r['address'],r['bytes']) for r in bindings.rows(native,image,at)}
            actual={(int(r['address'],16),r['bytes'].lower()) for r in fn['instructions']}
            if wanted<=actual:available.add(at)
    if available!=needed:raise ValueError('Version prepare exports lack complete two-root coverage')


def report_valid(report,context,sha):
    if (report.get('source_sha256')!=context['source_sha256'] or report.get('scope')!=SCOPE or report.get('method')!='bounded_native'
            or report.get('network_used') is not False or report.get('profile_activated') is not False or report.get('runtime_activated') is not False
            or report.get('proof')!=context.get('transfer_proof') or report.get('context_sha256')!=sha
            or len(report.get('cases',[]))!=64 or not all(r.get('guards') is True for r in report['cases'])
            or any(report.get(name) is not False for name in ('native_nm_used','native_system_used','native_combiners_used','native_platform_used'))):
        raise ValueError('Version prepare lacks its bounded semantic proof')


def published_contexts(root,registry,*,value=None):
    p=Path(root)/'knowledge'/INDEX/'index.json'
    if value is None:
        if not p.is_file():return []
        value=json.loads(p.read_text('utf-8'))
    if value.get('schema')!=1 or not isinstance(value.get('contexts'),list) or len(value['contexts'])>4096:raise ValueError('Invalid generated preparation index')
    known={r['source_sha256']:r['order'] for r in registry['releases']};seen=set();result=[]
    for row in value['contexts']:
        if set(row)!={'context','check','order'} or type(row['order']) is not int or row['order']<0:raise ValueError('Invalid generated preparation declaration')
        context=checked(root,row['context'],'generated-native-contexts');sha=context.get('source_sha256')
        if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha) or sha in seen or context.get('family')!=FAMILY:raise ValueError('Invalid generated preparation source')
        report_valid(checked(root,row['check'],'native-adapter-checks'),context,row['context']['sha256']);seen.add(sha)
        result.append((Path(row['context']['path']),context,known.get(sha,row['order'])))
    return result


def baseline_context(root,knowledge):
    api=load('native-release-registry');registry=api.read(knowledge);found=[]
    for p in (Path(knowledge)/'native-contexts').glob('version-prepare-*.json'):
        c=json.loads(p.read_text('utf-8'));identity=api.context_identity(p,c,registry)
        if identity and identity[1]==FAMILY:found.append((p,c,next(r['order'] for r in registry['releases'] if r['id']==identity[0])))
    found.extend(published_contexts(root,registry))
    if not found:raise ValueError('No reviewed Version prepare baseline')
    return max(found,key=lambda r:(r[2],str(r[0])))[:2]


def target_archive(root,knowledge,sha):
    registry=load('native-release-registry').read(knowledge)
    found=[(p,c) for p,c,_ in load('update-native-archive-wire').published_contexts(root,registry) if c['source_sha256']==sha]
    if len(found)!=1:raise ValueError('A reviewed target archive-wire context is required')
    return found[0]


def plan_inputs(index,args,sha):
    p,base=baseline_context(args.root,args.knowledge);archive_path,_=target_archive(args.root,args.knowledge,sha)
    contexts={str(f):index.digest(f) for f in (Path(args.knowledge)/'native-contexts').glob('version-prepare-*.json')};contexts[str(p)]=index.digest(p)
    return dict(source=sha,tools=tools(),registry=index.digest(Path(args.knowledge)/'native-release-registry.json'),baselines=contexts,
        baseline_exports={str(Path(args.root)/'ghidra/request-exports'/base['source_sha256']/run/'details.json'):index.digest(
            Path(args.root)/'ghidra/request-exports'/base['source_sha256']/run/'details.json') for run in base['exports']},
        archive=dict(path=str(archive_path),sha256=index.digest(archive_path)))


def planned(context,proof):
    return dict(state='planned',source_sha256=context['source_sha256'],context={k:v for k,v in context.items() if k!='exports'},
        exports=sorted(hex(a) for a in roots(context)),dependencies=tools(),artifacts={proof['baseline']['path']:proof['baseline']['sha256'],
            proof['archive']['path']:proof['archive']['sha256'],context['transfer_proof']['path']:context['transfer_proof']['sha256']})


def discover(index,args,sha):
    registry=load('native-release-registry').read(args.knowledge)
    existing=[c for _,c,_ in published_contexts(args.root,registry) if c['source_sha256']==sha]
    if existing:
        c=existing[0];validate(index,args,c);return planned(c,checked(args.root,c['transfer_proof'],PROOFS))
    archive_path,archive=target_archive(args.root,args.knowledge,sha);load('update-native-archive-wire').validate(index,args,archive)
    p,base=baseline_context(args.root,args.knowledge)
    if base.get('transfer_proof'):validate(index,args,base)
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    before=args.source_store.image(native,base['source_sha256']);after=args.source_store.image(native,sha)
    export_coverage(args.root,base,native,bindings,before);context,relocation=transfer(native,bindings,before,after,base,archive)
    proof=load('update-native-contexts').receipt(args.root,PROOFS,dict(schema=1,adapter=ADAPTER,scope=SCOPE,baseline=dict(path=str(p),sha256=digest(p)),
        archive=dict(path=str(archive_path),sha256=digest(archive_path)),target=context,relocation=relocation,tools=tools(),runtime_activated=False))
    context=dict(context,transfer_proof=proof);return planned(context,checked(args.root,proof,PROOFS))


def validate(index,args,context,seen=None):
    pointer=context['transfer_proof'];proof=checked(args.root,pointer,PROOFS);seen=set(seen or ())
    if pointer['sha256'] in seen or len(seen)>=32:raise ValueError('Version prepare proof cycle/depth exceeded')
    seen.add(pointer['sha256'])
    if (proof.get('schema')!=1 or proof.get('adapter')!=ADAPTER or proof.get('scope')!=SCOPE or proof.get('tools')!=tools()
            or proof.get('runtime_activated') is not False or context.get('layout')!=LAYOUT or proof.get('target')!=plain(context)):
        raise ValueError('Version prepare proof fields, tools or layout differ')
    p=Path(proof['baseline']['path']).resolve()
    if not (p.is_relative_to((HERE/'knowledge/native-contexts').resolve()) or p.is_relative_to((Path(args.root)/'knowledge/generated-native-contexts').resolve())):
        raise ValueError('Version prepare baseline outside reviewed contexts')
    if digest(p)!=proof['baseline']['sha256']:raise ValueError('Version prepare baseline changed')
    baseline=json.loads(p.read_text('utf-8'))
    if baseline.get('transfer_proof'):validate(index,args,baseline,seen)
    archive=checked(args.root,proof['archive'],'generated-native-contexts');load('update-native-archive-wire').validate(index,args,archive)
    if archive['source_sha256']!=context['source_sha256']:raise ValueError('Version prepare archive source differs')
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,context['source_sha256'])
    export_coverage(args.root,baseline,native,bindings,before)
    target,relocation=transfer(native,bindings,before,after,baseline,archive)
    if target!=proof['target'] or relocation!=proof['relocation']:raise ValueError('Version prepare relocated data/calls differ')
    if context.get('exports'):export_coverage(args.root,context,native,bindings,after)
    return context


def materialize(index,args,sha,plan,database):
    c=copy.deepcopy(plan['context']);workflow=load('research-workflow');db=index.open_index(database);exports={}
    try:
        for at in plan['exports']:
            state=workflow.function_state(index,db,sha,at)
            if state['state']!='ready':raise ValueError('Version prepare target export missing: '+at)
            for r in state['variants']:
                p=Path(r['artifact']).resolve()
                if r['completed'] and p.is_relative_to((Path(args.root)/'ghidra/request-exports'/sha).resolve()) and p.name=='details.json':exports[p.parent.name]=index.digest(p)
    finally:db.close()
    c['exports']=exports;validate(index,args,c);target=load('update-native-contexts').receipt(args.root,'generated-native-contexts',c)
    artifacts={**plan['artifacts'],target['path']:target['sha256']}
    artifacts.update({str(Path(args.root)/'ghidra/request-exports'/sha/run/'details.json'):expected for run,expected in exports.items()})
    return dict(checks=[dict(id='native-auto-version-prepare',adapter=ADAPTER,scope=SCOPE,contracts=[],context=target,
        proof=c['transfer_proof'],dependencies=tools(),artifacts=artifacts)],queue=[])


def execute(index,args,sha,declaration):
    c=checked(args.root,declaration['context'],'generated-native-contexts')
    if declaration.get('adapter')!=ADAPTER or declaration.get('scope')!=SCOPE or c['source_sha256']!=sha or declaration['dependencies']!=tools():
        raise ValueError('Version prepare check declaration differs')
    for p,expected in declaration['artifacts'].items():
        if index.digest(p)!=expected:raise ValueError('Version prepare artifact changed')
    validate(index,args,c);r=load('verify-version-prepare-context').verify(c,args.root)
    r.update(scope=SCOPE,proof=c['transfer_proof'],context_sha256=declaration['context']['sha256'],runtime_activated=False)
    report_valid(r,c,declaration['context']['sha256']);p=load('update-native-contexts').receipt(args.root,'native-adapter-checks',r)
    return dict(id=declaration['id'],state='passed',report=p['path'],sha256=p['sha256'],scope=SCOPE,runtime_activated=False,profile_activated=False)


def publish(index,args,sha,declaration,outcome):
    if outcome.get('state')!='passed':raise ValueError('Only a passed Version prepare context can be published')
    c=checked(args.root,declaration['context'],'generated-native-contexts');validate(index,args,c)
    if c['source_sha256']!=sha:raise ValueError('Version prepare publication source differs')
    check=dict(path=outcome['report'],sha256=outcome['sha256']);report_valid(checked(args.root,check,'native-adapter-checks'),c,declaration['context']['sha256'])
    registry=load('native-release-registry').read(args.knowledge);published_contexts(args.root,registry)
    p=Path(args.root)/'knowledge'/INDEX/'index.json';old=json.loads(p.read_text('utf-8')) if p.is_file() else dict(schema=1,contexts=[])
    entries=[r for r in old['contexts'] if checked(args.root,r['context'],'generated-native-contexts')['source_sha256']!=sha]
    ranks={r['source_sha256']:r['order'] for r in registry['releases']};rank=ranks.get(sha,max([r['order'] for r in registry['releases']]+[r['order'] for r in entries])+1)
    entries.append(dict(context=declaration['context'],check=check,order=rank));value=dict(schema=1,contexts=sorted(entries,key=lambda r:(r['order'],r['context']['path'])))
    published_contexts(args.root,registry,value=value);w=load('research-workflow');w.atomic(p,w.canonical(value))
    return dict(path=str(p),sha256=index.digest(p))
