"""Portable Login preparation with source-bound native SDK getters and leaves.

Cache/store/string/backend boundaries remain synthetic fixtures. No live SDK,
authorization, metadata writer or network compatibility is admitted here.
"""
import copy
import hashlib
import itertools
import json
from pathlib import Path
import re
from importlib.util import spec_from_file_location,module_from_spec

HERE=Path(__file__).resolve().parent
ADAPTER='login-sdk-v1'
FAMILY='login-prepare-sdk'
SCOPE='bounded_native_login_sdk_prepare'
INDEX='generated-login-sdk'
PROOFS='native-login-sdk-proofs'
NATIVE_NAMES={'sdk_mode','sdk_main_text','sdk_value','sdk_manager','sdk_flag',
              'sdk_extra_flag','owner_number','language','flags_manager'}
FUNCTIONS={'sdk_mode','sdk_main_text','sdk_value'}
LEAF_NAMES=NATIVE_NAMES-FUNCTIONS
INNER_NAMES={'mode_text','main_store','value_store','cache_resolve','main_string','assign_counted'}
LAYOUT=dict(abi='win64',packet_bytes=320,executed_roots=5,returning_leaves=6,
    synthetic_cache_offset=272,retained_string_offset=88,max_allocation=2048,
    cache_cases=['warm','resolve','absent'],native_metadata=False)
OWN_TOOLS=('update-native-login-sdk.py','verify-login-prepare-context.py','login-sdk-fixtures.py',
           'native-release-registry.py','research-workflow.py')


def load(name):
    spec=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):return load('update-native-contexts').digest(path)
def tools():return {**load('update-native-login-prepare').tools(),**{str(HERE/name):digest(HERE/name) for name in OWN_TOOLS}}
def checked(root,item,category):return load('update-native-contexts').checked(root,item,category)
def image_bytes(image,at,size):return load('update-native-contexts').image_bytes(image,at,size)


def plain(context):
    value=copy.deepcopy(context)
    for key in ('exports','transfer_proof','release_id'):value.pop(key,None)
    value.get('native_sdk',{}).pop('exports',None)
    return value


def base_context(context):
    value=copy.deepcopy(context)
    for key in ('native_sdk','native_metadata','exports','transfer_proof','release_id','family','layout','function_budget'):
        value.pop(key,None)
    return value


def validate_sdk_scope(context):
    sdk=context.get('native_sdk',{})
    if ('native_metadata' in context or 'function_budget' in context
            or set(sdk.get('functions',{}))!=FUNCTIONS or len(sdk.get('leaves',{}))!=6
            or set(sdk.get('native_names',[]))!=NATIVE_NAMES or len(sdk['native_names'])!=9
            or set(sdk.get('fixtures',{}))!=INNER_NAMES or set(sdk.get('globals',{}))!={'manager','language','flags'}
            or set(sdk.get('mode_literals',{}))!={'0','1','2'}):
        raise ValueError('Login SDK execution/layout scope differs')
    executable={int(context[k],16) for k in ('prepare','constructor')}
    executed={int(v,16) for v in sdk['functions'].values()}
    leaves={int(v,16) for v in sdk['leaves']}
    fixture={key:int(context['fixtures'][key],16) for key in NATIVE_NAMES}
    if len(executable)!=2 or len(executed)!=3 or len(leaves)!=6 or executable&(executed|leaves) or executed&leaves:
        raise ValueError('Login SDK roots/leaves alias')
    if set(fixture.values())!=executed|leaves or len(set(fixture.values()))!=9:
        raise ValueError('Login SDK native roles do not match fixture links')
    if any(int(sdk['functions'][name],16)!=fixture[name] for name in FUNCTIONS):
        raise ValueError('Login SDK getter role differs from direct Login caller')
    if {fixture[name] for name in LEAF_NAMES}!=leaves:
        raise ValueError('Login SDK leaf role differs from direct Login caller')
    inner={int(v,16) for v in sdk['fixtures'].values()}
    outer={int(value,16) for key,value in context['fixtures'].items() if key not in NATIVE_NAMES}
    if len(inner)!=6 or inner&(executable|executed|leaves|outer|{int(context['helpers']['memcpy'],16)}):
        raise ValueError('Login SDK inner fixture aliases admitted code')
    return executable|executed


def roots(context):return validate_sdk_scope(context)


def leaf_rows(native,image,at,spec,*,baseline=False):
    declared=bytes.fromhex(spec['bytes'])
    if not 1<=len(declared)<=512 or hashlib.sha256(declared).hexdigest()!=spec['sha256']:
        raise ValueError('Login SDK leaf declared bytes/hash differ')
    actual=image_bytes(image,at,len(declared))
    if baseline and actual!=declared:raise ValueError('Login SDK baseline leaf changed')
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    instructions=list(decoder.disasm(actual,at))
    if (not instructions or sum(i.size for i in instructions)!=len(actual) or instructions[-1].mnemonic!='ret'
            or any(i.group(native.capstone.CS_GRP_CALL) or i.group(native.capstone.CS_GRP_JUMP) for i in instructions)):
        raise ValueError('Login SDK leaf must be a complete return with no calls/jumps')
    return [dict(address=i.address,bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str,
        call=False,branch=False,direct_target=None,rip_references=[i.address+i.size+op.mem.disp for op in i.operands
            if op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP]) for i in instructions]


def wide_literal(image,at):
    raw=bytearray()
    for offset in range(0,512,2):
        value=image_bytes(image,at+offset,2)
        if value==b'\0\0':return raw.decode('utf-16le'),bytes(raw)+value
        raw.extend(value)
    raise ValueError('Login SDK wide literal exceeds bound')


def call_sites(native,bindings,image,functions):
    return {hex(r['address']):dict(target=hex(r['direct_target']) if r['direct_target'] is not None else r['operands'])
        for at in functions.values() for r in bindings.rows(native,image,int(at,16)) if r['call']}


def metadata_fields(native,bindings,image,collector,wide_string,consumer):
    rows=bindings.rows(native,image,collector);result=[]
    for i,row in enumerate(rows):
        if len(row['rip_references'])!=1 or row['mnemonic']!='lea' or not row['operands'].startswith('rdx, '):continue
        at=row['rip_references'][0]
        if image_bytes(image,at,4)!=b'I\0_\0':continue
        name,_=wide_literal(image,at)
        if (i+5>=len(rows) or rows[i+2]['direct_target']!=wide_string or rows[i+5]['direct_target']!=consumer):
            raise ValueError('Login SDK metadata key/consumer call linkage differs')
        result.append(dict(key=name,literal=hex(at),call_site=hex(rows[i+5]['address'])))
    if len(result)!=27:raise ValueError('Login SDK static metadata field count differs')
    return result


def inner_boundaries(before,after,baseline,current):
    """Unexecuted hook boundaries, including the one reviewed dispatch thunk."""
    result={}
    for role,text in current.items():
        at=int(text,16);old=int(baseline[role],16)
        if role=='cache_resolve':
            # This fixture replaces a virtual dispatch thunk, not its unknown
            # destination. Its exact ten bytes and six trap padding bytes are
            # the reviewed boundary; there is no unwind entry for the thunk.
            expected=bytes.fromhex('488b0148ffa010040000')+b'\xcc'*6
            if any(address%16 or image_bytes(image,address,16)!=expected for image,address in ((before,old),(after,at))):
                raise ValueError('Login SDK cache resolver fixture dispatch thunk changed')
            result[role]=dict(address=text,kind='fixture-dispatch-thunk',bytes=expected[:10].hex(),
                scope='Replaced hook; virtual dispatch destination is not executed or admitted')
        else:
            for image,address in ((before,old),(after,at)):
                part=image.containing(address)
                if part is None or image.roots[part][0]+image.pe.base!=address:
                    raise ValueError('Login SDK inner fixture needs a concrete unwind boundary: '+role)
            result[role]=dict(address=text,kind='unwind-fixture',scope='Replaced hook; body is not executed')
    return result


def transfer(native,bindings,before,after,baseline,target_base,archive):
    """Prove the SDK baseline's base caller again; newer base roles cannot bypass it."""
    roots(baseline);base_api=load('update-native-login-prepare');edges=load('update-native-archive-wire')
    current,base_relation=base_api.transfer(native,bindings,before,after,base_context(baseline),archive)
    if base_api.plain(current)!=base_api.plain(target_base):
        raise ValueError('Login SDK base caller differs from published target preparation')
    mapping={int(a,16):int(b,16) for a,b in base_relation['mapping'].items()}
    sdk=baseline['native_sdk']
    for role,text in sdk['functions'].items():
        old=int(text,16)
        if old not in mapping:raise ValueError('Login SDK getter has no exact Login call constraint')
        edges.pair_rows(native,bindings.rows(native,before,old),bindings.rows(native,after,mapping[old]),mapping)
    if call_sites(native,bindings,before,sdk['functions'])!=sdk['call_sites']:
        raise ValueError('Login SDK baseline getter call-site declarations differ')
    leaves={}
    for text,spec in sdk['leaves'].items():
        old=int(text,16)
        if old not in mapping:raise ValueError('Login SDK leaf lacks a direct caller constraint')
        target=mapping[old]
        old_rows=leaf_rows(native,before,old,spec,baseline=True);new_rows=leaf_rows(native,after,target,spec)
        edges.pair_rows(native,old_rows,new_rows,mapping)
        raw=image_bytes(after,target,len(bytes.fromhex(spec['bytes'])))
        leaves[hex(target)]=dict(bytes=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
    def mapped(text):
        old=int(text,16)
        if old not in mapping:raise ValueError('Login SDK undeclared address relocation: '+text)
        return hex(mapping[old])
    mode_literals={};literals=[]
    for mode,text in sdk['mode_literals'].items():
        target=int(mapped(text),16);old_value,old_raw=wide_literal(before,int(text,16));value,raw=wide_literal(after,target)
        if value!=old_value or raw!=old_raw:raise ValueError('Login SDK mode literal changed')
        mode_literals[mode]=hex(target);literals.append(dict(mode=mode,address=hex(target),bytes=raw.hex()))
    if len({row['bytes'] for row in literals})!=3:raise ValueError('Login SDK mode literals are not distinct')
    globals_={key:mapped(text) for key,text in sdk['globals'].items()};global_inputs=[]
    data_input=base_api.data_input
    for key,text in sdk['globals'].items():
        old_input=data_input(before,int(text,16),8);new_input=data_input(after,int(globals_[key],16),8)
        if old_input!=new_input:raise ValueError('Login SDK synthetic global declaration changed: '+key)
        global_inputs.append(dict(role=key,address=globals_[key],input=new_input,scope='Seeded synthetic pointer, not a real SDK object'))
    metadata=sdk['metadata'];old_collector=int(metadata['collector'],16)
    if old_collector not in mapping:raise ValueError('Login SDK static metadata collector lacks a Login call link')
    target_collector=mapping[old_collector]
    edges.pair_rows(native,bindings.rows(native,before,old_collector),bindings.rows(native,after,target_collector),mapping)
    old_fields=metadata_fields(native,bindings,before,old_collector,int(baseline['fixtures']['wide_string'],16),int(metadata['consumer'],16))
    if old_fields!=metadata['fields']:raise ValueError('Login SDK baseline metadata fields differ')
    consumer=int(mapped(metadata['consumer']),16)
    new_fields=metadata_fields(native,bindings,after,target_collector,int(current['fixtures']['wide_string'],16),consumer)
    if [row['key'] for row in old_fields]!=[row['key'] for row in new_fields]:
        raise ValueError('Login SDK metadata keys/order changed')
    for old,new in zip(old_fields,new_fields):
        if mapping[int(old['literal'],16)]!=int(new['literal'],16) or mapping[int(old['call_site'],16)]!=int(new['call_site'],16):
            raise ValueError('Login SDK metadata literal/call relocation differs')
    metadata_boundary=after.containing(consumer)
    if metadata_boundary is None or after.roots[metadata_boundary][0]+after.pe.base!=consumer:
        raise ValueError('Login SDK unexecuted metadata consumer is not an unwind entry')
    inners={key:mapped(text) for key,text in sdk['fixtures'].items()}
    boundaries=inner_boundaries(before,after,sdk['fixtures'],inners)
    current['family']=FAMILY;current['layout']=LAYOUT
    current['native_sdk']=dict(functions={key:mapped(at) for key,at in sdk['functions'].items()},leaves=leaves,
        globals=globals_,native_names=list(sdk['native_names']),fixtures=inners,mode_literals=mode_literals,
        call_sites=call_sites(native,bindings,after,{key:mapped(at) for key,at in sdk['functions'].items()}),
        metadata=dict(collector=hex(target_collector),consumer=hex(consumer),fields=new_fields))
    roots(current)
    # Every SDK RIP reference must be one of the reviewed synthetic globals or
    # mode literals; arbitrary static data cannot hide behind the shape mask.
    known_data={int(v,16) for v in mode_literals.values()}|{int(v,16) for v in globals_.values()}
    for role,at in current['native_sdk']['functions'].items():
        if any(ref not in known_data for row in bindings.rows(native,after,int(at,16)) for ref in row['rip_references']):
            raise ValueError('Login SDK getter has undeclared static data')
    for at,spec in leaves.items():
        if any(ref not in known_data for row in leaf_rows(native,after,int(at,16),spec) for ref in row['rip_references']):
            raise ValueError('Login SDK leaf has undeclared synthetic global')
    return current,dict(base=base_relation,mapping={hex(a):hex(b) for a,b in sorted(mapping.items())},mode_literals=literals,
        globals=global_inputs,inner_fixtures=boundaries,static_metadata=dict(collector=hex(target_collector),consumer=hex(consumer),fields=new_fields,
            scope='Field keys and direct consumer links only; collector and consumer are not executed'),
        scope_limits=['Five roots and six return leaves execute with stable synthetic SDK manager/cache/handles.',
            'Inner SDK cache/string/resolver, metadata collection, OS, backend, allocation and send remain fixtures.'])


def export_coverage(root,context,native,bindings,image):
    needed=roots(context);available=set();declared=dict(context.get('exports',{}))
    for run,sha in context['native_sdk'].get('exports',{}).items():
        if run in declared and declared[run]!=sha:raise ValueError('Conflicting Login SDK export hashes')
        declared[run]=sha
    for run,expected in declared.items():
        if Path(run).name!=run or not run.startswith('run-'):raise ValueError('Invalid Login SDK export name')
        p=Path(root)/'ghidra/request-exports'/context['source_sha256']/run/'details.json'
        if digest(p)!=expected:raise ValueError('Login SDK export changed')
        report=json.loads(p.read_text('utf-8'))
        if report.get('new_source_sha256',report.get('source_sha256'))!=context['source_sha256']:raise ValueError('Login SDK export source differs')
        for fn in report['functions']:
            at=int(fn['address'],16)
            if at not in needed or fn.get('decompilation_completed') is not True:continue
            wanted={(row['address'],row['bytes']) for row in bindings.rows(native,image,at)}
            actual={(int(row['address'],16),row['bytes'].lower()) for row in fn['instructions']}
            if wanted<=actual:available.add(at)
    if available!=needed:raise ValueError('Login SDK exports lack five complete roots')


def report_valid(report,context,sha):
    if (report.get('source_sha256')!=context['source_sha256'] or report.get('scope')!=SCOPE or report.get('method')!='bounded_native'
            or report.get('network_used') is not False or report.get('profile_activated') is not False or report.get('runtime_activated') is not False
            or report.get('proof')!=context.get('transfer_proof') or report.get('context_sha256')!=sha
            or report.get('native_sdk_used') is not True or report.get('native_metadata_used') is not False
            or len(report.get('cases',[]))!=2016 or not all(row.get('guards') is True for row in report['cases'])
            or {row.get('cache_case') for row in report['cases']}!={'warm','resolve','absent'}
            or len(report.get('metadata_fields',[]))!=27 or report['metadata_fields']!=context['native_sdk']['metadata']['fields']):
        raise ValueError('Login SDK lacks its bounded semantic integration proof')
    fields=('scenario','selector','empty','send_return','poison','cache_case')
    expected=set(itertools.product([row[0] for row in load('verify-login-prepare-context').SCENARIOS],
        (0,1,2,3,4,255),(False,True),(0,1),(0x55,0xaa),('warm','resolve','absent')))
    actual={tuple(row.get(key) for key in fields) for row in report['cases']}
    if len(expected)!=2016 or actual!=expected:
        raise ValueError('Login SDK scenario/cache/poison matrix is incomplete or duplicated')


def published_contexts(root,registry,*,value=None):
    p=Path(root)/'knowledge'/INDEX/'index.json'
    if value is None:
        if not p.is_file():return []
        value=json.loads(p.read_text('utf-8'))
    if value.get('schema')!=1 or not isinstance(value.get('contexts'),list) or len(value['contexts'])>4096:
        raise ValueError('Invalid generated Login SDK index')
    ranks={row['source_sha256']:row['order'] for row in registry['releases']};seen=set();result=[]
    for row in value['contexts']:
        if set(row)!={'context','check','order'} or type(row['order']) is not int or row['order']<0:raise ValueError('Invalid generated Login SDK declaration')
        context=checked(root,row['context'],'generated-native-contexts');sha=context.get('source_sha256')
        if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha) or sha in seen or context.get('family')!=FAMILY:
            raise ValueError('Invalid generated Login SDK source/family')
        report_valid(checked(root,row['check'],'native-adapter-checks'),context,row['context']['sha256']);seen.add(sha)
        result.append((Path(row['context']['path']),context,ranks.get(sha,row['order'])))
    return result


def baseline_context(root,knowledge):
    api=load('native-release-registry');registry=api.read(knowledge);found=[]
    for p in (Path(knowledge)/'native-contexts').glob('login-prepare-sdk-*.json'):
        c=json.loads(p.read_text('utf-8'));identity=api.context_identity(p,c,registry)
        if identity and identity[1]==FAMILY:found.append((p,c,next(r['order'] for r in registry['releases'] if r['id']==identity[0])))
    found.extend(published_contexts(root,registry))
    if not found:raise ValueError('No reviewed Login SDK integration baseline')
    return max(found,key=lambda row:(row[2],str(row[0])))[:2]


def target_base(root,knowledge,sha):
    registry=load('native-release-registry').read(knowledge)
    found=[(p,c) for p,c,_ in load('update-native-login-prepare').published_contexts(root,registry) if c['source_sha256']==sha]
    if len(found)!=1:raise ValueError('A reviewed target base Login context is required')
    return found[0]


def plan_inputs(index,args,sha):
    p,baseline=baseline_context(args.root,args.knowledge);base_path,_=target_base(args.root,args.knowledge,sha)
    contexts={str(f):index.digest(f) for f in (Path(args.knowledge)/'native-contexts').glob('login-prepare-sdk-*.json')};contexts[str(p)]=index.digest(p)
    declared=dict(baseline.get('exports',{}),**baseline['native_sdk'].get('exports',{}))
    return dict(source=sha,tools=tools(),registry=index.digest(Path(args.knowledge)/'native-release-registry.json'),baselines=contexts,
        baseline_exports={str(Path(args.root)/'ghidra/request-exports'/baseline['source_sha256']/run/'details.json'):index.digest(
            Path(args.root)/'ghidra/request-exports'/baseline['source_sha256']/run/'details.json') for run in declared},
        base_login=dict(path=str(base_path),sha256=index.digest(base_path)))


def planned(context,proof):
    return dict(state='planned',source_sha256=context['source_sha256'],context={key:value for key,value in context.items() if key!='exports'},
        exports=sorted((hex(at) for at in roots(context)),key=lambda at:int(at,16)),dependencies=tools(),
        artifacts={proof['baseline']['path']:proof['baseline']['sha256'],proof['base_login']['path']:proof['base_login']['sha256'],
            context['transfer_proof']['path']:context['transfer_proof']['sha256']})


def discover(index,args,sha):
    registry=load('native-release-registry').read(args.knowledge)
    existing=[c for _,c,_ in published_contexts(args.root,registry) if c['source_sha256']==sha]
    if existing:
        c=existing[0];validate(index,args,c);return planned(c,checked(args.root,c['transfer_proof'],PROOFS))
    base_path,base=target_base(args.root,args.knowledge,sha);load('update-native-login-prepare').validate(index,args,base)
    p,baseline=baseline_context(args.root,args.knowledge)
    if baseline.get('transfer_proof'):validate(index,args,baseline)
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,sha)
    export_coverage(args.root,baseline,native,bindings,before)
    base_proof=checked(args.root,base['transfer_proof'],'native-login-prepare-proofs')
    archive=checked(args.root,base_proof['archive'],'generated-native-contexts')
    context,relocation=transfer(native,bindings,before,after,baseline,base,archive)
    proof=load('update-native-contexts').receipt(args.root,PROOFS,dict(schema=1,adapter=ADAPTER,scope=SCOPE,
        baseline=dict(path=str(p),sha256=digest(p)),base_login=dict(path=str(base_path),sha256=digest(base_path)),
        target=context,relocation=relocation,tools=tools(),runtime_activated=False))
    context=dict(context,transfer_proof=proof);return planned(context,checked(args.root,proof,PROOFS))


def validate(index,args,context,seen=None):
    pointer=context['transfer_proof'];proof=checked(args.root,pointer,PROOFS);seen=set(seen or ())
    if pointer['sha256'] in seen or len(seen)>=32:raise ValueError('Login SDK proof cycle/depth exceeded')
    seen.add(pointer['sha256'])
    if (proof.get('schema')!=1 or proof.get('adapter')!=ADAPTER or proof.get('scope')!=SCOPE or proof.get('tools')!=tools()
            or proof.get('runtime_activated') is not False or context.get('layout')!=LAYOUT or proof.get('target')!=plain(context)):
        raise ValueError('Login SDK proof fields, tools or layout differ')
    p=Path(proof['baseline']['path']).resolve()
    if not (p.is_relative_to((HERE/'knowledge/native-contexts').resolve()) or p.is_relative_to((Path(args.root)/'knowledge/generated-native-contexts').resolve())):
        raise ValueError('Login SDK baseline outside reviewed contexts')
    if digest(p)!=proof['baseline']['sha256']:raise ValueError('Login SDK baseline changed')
    baseline=json.loads(p.read_text('utf-8'))
    if baseline.get('transfer_proof'):validate(index,args,baseline,seen)
    base=checked(args.root,proof['base_login'],'generated-native-contexts');load('update-native-login-prepare').validate(index,args,base)
    if base['source_sha256']!=context['source_sha256']:raise ValueError('Login SDK target base source differs')
    base_proof=checked(args.root,base['transfer_proof'],'native-login-prepare-proofs')
    archive=checked(args.root,base_proof['archive'],'generated-native-contexts')
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,context['source_sha256'])
    export_coverage(args.root,baseline,native,bindings,before)
    target,relocation=transfer(native,bindings,before,after,baseline,base,archive)
    if target!=proof['target'] or relocation!=proof['relocation']:raise ValueError('Login SDK relocated call/data/layout differs')
    if context.get('exports'):export_coverage(args.root,context,native,bindings,after)
    return context


def materialize(index,args,sha,plan,database):
    c=copy.deepcopy(plan['context']);db=index.open_index(database);exports={};workflow=load('research-workflow')
    try:
        for at in plan['exports']:
            state=workflow.function_state(index,db,sha,at)
            if state['state']!='ready':raise ValueError('Login SDK target root export missing: '+at)
            for row in state['variants']:
                p=Path(row['artifact']).resolve()
                if row['completed'] and p.is_relative_to((Path(args.root)/'ghidra/request-exports'/sha).resolve()) and p.name=='details.json':exports[p.parent.name]=index.digest(p)
    finally:db.close()
    c['exports']=exports;c['native_sdk']['exports']=exports.copy();validate(index,args,c)
    target=load('update-native-contexts').receipt(args.root,'generated-native-contexts',c)
    artifacts={**plan['artifacts'],target['path']:target['sha256']}
    artifacts.update({str(Path(args.root)/'ghidra/request-exports'/sha/run/'details.json'):expected for run,expected in exports.items()})
    return dict(checks=[dict(id='native-auto-login-sdk',adapter=ADAPTER,scope=SCOPE,contracts=[],context=target,proof=c['transfer_proof'],dependencies=tools(),artifacts=artifacts)],queue=[])


def execute(index,args,sha,declaration):
    c=checked(args.root,declaration['context'],'generated-native-contexts')
    if declaration.get('adapter')!=ADAPTER or declaration.get('scope')!=SCOPE or c['source_sha256']!=sha or declaration['dependencies']!=tools():
        raise ValueError('Login SDK check declaration differs')
    for p,expected in declaration['artifacts'].items():
        if index.digest(p)!=expected:raise ValueError('Login SDK artifact changed')
    validate(index,args,c);r=load('verify-login-prepare-context').verify(c,args.root)
    r.update(scope=SCOPE,proof=c['transfer_proof'],context_sha256=declaration['context']['sha256'],runtime_activated=False)
    report_valid(r,c,declaration['context']['sha256']);p=load('update-native-contexts').receipt(args.root,'native-adapter-checks',r)
    return dict(id=declaration['id'],state='passed',report=p['path'],sha256=p['sha256'],scope=SCOPE,runtime_activated=False,profile_activated=False)


def publish(index,args,sha,declaration,outcome):
    if outcome.get('state')!='passed':raise ValueError('Only a passed Login SDK context can be published')
    c=checked(args.root,declaration['context'],'generated-native-contexts');validate(index,args,c)
    if c['source_sha256']!=sha:raise ValueError('Login SDK publication source differs')
    check=dict(path=outcome['report'],sha256=outcome['sha256']);report_valid(checked(args.root,check,'native-adapter-checks'),c,declaration['context']['sha256'])
    registry=load('native-release-registry').read(args.knowledge);published_contexts(args.root,registry)
    p=Path(args.root)/'knowledge'/INDEX/'index.json';old=json.loads(p.read_text('utf-8')) if p.is_file() else dict(schema=1,contexts=[])
    entries=[row for row in old['contexts'] if checked(args.root,row['context'],'generated-native-contexts')['source_sha256']!=sha]
    ranks={row['source_sha256']:row['order'] for row in registry['releases']};rank=ranks.get(sha,max([row['order'] for row in registry['releases']]+[row['order'] for row in entries])+1)
    entries.append(dict(context=declaration['context'],check=check,order=rank));value=dict(schema=1,contexts=sorted(entries,key=lambda row:(row['order'],row['context']['path'])))
    published_contexts(args.root,registry,value=value);w=load('research-workflow');w.atomic(p,w.canonical(value))
    return dict(path=str(p),sha256=index.digest(p))
