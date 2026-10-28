"""Portable whole string writer, with explicit non-executed allocator/OS boundaries.

The existing UTF-8 proof engine remains byte-for-byte unchanged. Writer exports
are real target Ghidra materials, collected by the normal serialized collector.
"""
import copy
import json
from pathlib import Path
import re
import struct

from importlib.util import spec_from_file_location, module_from_spec

HERE=Path(__file__).resolve().parent
ADAPTER='string-writer-v1'
SCOPE='bounded_native_string_writer'
TOOLS=('update-native-string-writer.py','verify-string-writer-context.py','verify-utf8-context.py',
       'update-native-harness.py','update-native-contexts.py','update-bindings.py',
       'build-native-entry-code.py','build-object-zero-init-code.py','extract-native-enums.py',
       'function-reuse-plan.py','audit-launcher-shape-11318.py')
LAYOUT=dict(abi='win64',archive_slot=40,fstring_bytes=16,std_string_bytes=32,
            max_allocation=8192,max_string_bytes=4095)
CALL_ROLES=('length','utf8_allocate','convert','memcpy','cpp_allocate','cpp_allocate',
            'memcpy','utf8_free','cpp_free','security_check','exception_0','exception_1')


def load(name):
    spec=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=module_from_spec(spec);spec.loader.exec_module(module);return module


def tools():
    digest=load('update-native-contexts').digest
    return {str(HERE/name):digest(HERE/name) for name in TOOLS}


def checked(root,item,category):return load('update-native-contexts').checked(root,item,category)


def cookie_address(image):
    """SecurityCookie is a declared PE32+ load-config input, not an arbitrary RIP ref."""
    raw=image.data;pe=struct.unpack_from('<I',raw,60)[0];opt=pe+24
    if struct.unpack_from('<H',raw,opt)[0]!=0x20b:raise ValueError('Writer needs PE32+ load config')
    if struct.unpack_from('<I',raw,opt+108)[0]<=10:raise ValueError('Writer load config is absent')
    rva,size=struct.unpack_from('<II',raw,opt+112+10*8)
    if not rva or size<96:raise ValueError('Writer load config cookie is absent')
    offset=image.offset(rva)
    if struct.unpack_from('<I',raw,offset)[0]<96:raise ValueError('Writer load config cookie is truncated')
    return struct.unpack_from('<Q',raw,offset+88)[0]


def fixture_boundary(image,role,address,roles):
    location=image.containing(address)
    if location is not None and image.roots[location][0]+image.pe.base==address:return dict(kind='unwind-root')
    # Two reviewed allocator fixtures are compiler leaf tail thunks. They are
    # never executed or exported as fabricated unwind functions.
    raw=load('update-native-contexts').image_bytes(image,address,25)
    if role=='cpp_free' and raw[:1]==b'\xe9':
        target=address+5+struct.unpack_from('<i',raw,1)[0]
        if target==roles['utf8_free']:return dict(kind='free-tail',target=hex(target),size=5)
    prefix=bytes.fromhex('4885c9b801000000ba10000000480f45c1488bc8')
    if role=='cpp_allocate' and raw[:20]==prefix and raw[20:21]==b'\xe9':
        target=address+25+struct.unpack_from('<i',raw,21)[0];location=image.containing(target)
        if location is not None and image.roots[location][0]+image.pe.base==target:
            return dict(kind='allocate-tail',target=hex(target),size=25,alignment=16,minimum=1)
    raise ValueError('Writer fixture is not an explicit unwind root or reviewed tail: '+role)


def describe(native,bindings,image,at,utf8):
    """Extract all relocated edges after the entire instruction shape is matched."""
    common=load('update-native-contexts');rows=bindings.rows(native,image,at)
    locations={r['address'] for r in rows}
    if any(r['branch'] and not r['call'] and r['direct_target'] not in locations for r in rows):
        raise ValueError('Writer has an unreviewed external branch')
    direct=[r for r in rows if r['call'] and r['direct_target'] is not None]
    if len(direct)!=len(CALL_ROLES):raise ValueError('Writer direct call count differs')
    roles={}
    for role,row in zip(CALL_ROLES,direct):
        target=row['direct_target']
        if role in roles and roles[role]!=target:raise ValueError('Writer repeated fixture role differs')
        roles[role]=target
    if any(roles[key]!=int(utf8['bindings'][key],16) for key in ('length','convert')):
        raise ValueError('Writer UTF-8 callee differs from reviewed context')
    if roles['memcpy']!=int(utf8['helpers']['memcpy'],16):raise ValueError('Writer memcpy link differs')
    common.memcpy_identity(native,image,roles['memcpy'])
    executable={at,*(int(utf8['bindings'][k],16) for k in ('length','convert','encoder'))}
    fixture_roles={k:v for k,v in roles.items() if k not in ('length','convert')}
    if len(set(fixture_roles.values()))!=len(fixture_roles) or set(fixture_roles.values())&executable:
        raise ValueError('Writer fixture roles alias or overlap executable code')
    boundaries={}
    for role,address in fixture_roles.items():
        # memcpy is a reviewed import thunk; other fixtures must still name
        # concrete PE functions. Their bodies/side effects remain unexecuted.
        if role=='memcpy':continue
        boundaries[role]=fixture_boundary(image,role,address,roles)
    indirect=[r for r in rows if r['call'] and r['direct_target'] is None]
    if len(indirect)!=3 or indirect[1]['operands']!='qword ptr [rax + 0x28]':
        raise ValueError('Writer archive slot differs')
    slots=[r['rip_references'] for r in (indirect[0],indirect[2])]
    if len(slots[0])!=1 or slots[0]!=slots[1]:raise ValueError('Writer IAT slots differ')
    slot=slots[0][0]
    identity=load('build-object-zero-init-code').import_at(image.data,image,slot)
    if (identity['dll'].lower(),identity['name'])!=('api-ms-win-crt-runtime-l1-1-0.dll','_invalid_parameter_noinfo_noreturn'):
        raise ValueError('Writer IAT identity differs')
    refs=[r for r in rows if r['rip_references'] and not r['call']]
    cookie=cookie_address(image)
    if (len(refs)!=2 or refs[0]['mnemonic']!='mov' or refs[0]['rip_references']!=[cookie]
            or refs[1]['mnemonic']!='lea' or len(refs[1]['rip_references'])!=1):
        raise ValueError('Writer cookie/literal source differs')
    literal=refs[1]['rip_references'][0]
    if common.image_bytes(image,literal,2)!=b'\0\0':raise ValueError('Writer empty UTF-16 literal changed')
    return dict(fixtures=dict(archive_slot=40,**{key:hex(roles[key]) for key in (
        'utf8_allocate','utf8_free','cpp_allocate','cpp_free','security_check')}),
        writer_metadata=dict(cookie=hex(cookie),exception_calls=[hex(roles['exception_0']),hex(roles['exception_1'])],
            indirect=[r['operands'] for r in indirect],invalid_parameter_iat=hex(slot)),
        inputs=dict(cookie=dict(address=hex(cookie),bytes=common.image_bytes(image,cookie,8).hex()),
            empty_literal=dict(address=hex(literal),bytes='0000'),invalid_parameter_import=identity,fixture_boundaries=boundaries),
        calls=[dict(offset=r['address']-at,role=role) for role,r in zip(CALL_ROLES,direct)])


def published_contexts(root,registry,*,value=None):
    root=Path(root);path=root/'knowledge/generated-string-writers/index.json'
    if value is None:
        if not path.is_file():return []
        value=json.loads(path.read_text('utf-8'))
    if value.get('schema')!=1 or not isinstance(value.get('contexts'),list) or len(value['contexts'])>4096:
        raise ValueError('Invalid generated writer index')
    ranks={r['source_sha256']:r['order'] for r in registry['releases']};seen=set();result=[]
    for item in value['contexts']:
        if set(item)!={'context','check','order'} or type(item['order']) is not int or item['order']<0:
            raise ValueError('Invalid generated writer declaration')
        context=checked(root,item['context'],'generated-native-contexts')
        check=checked(root,item['check'],'native-adapter-checks')
        sha=context.get('source_sha256')
        if (not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha)
                or context.get('family')!='string-writer' or check.get('source_sha256')!=sha or sha in seen
                or check.get('scope')!=SCOPE or check.get('method')!='bounded_native'
                or check.get('runtime_activated') is not False or check.get('network_used') is not False
                or check.get('profile_activated') is not False or check.get('proof')!=context.get('transfer_proof')
                or check.get('context_sha256')!=item['context']['sha256']
                or check.get('bindings')!=context.get('bindings') or len(check.get('cases',[]))!=228
                or not all(c.get('guards') is True for c in check['cases'])):
            raise ValueError('Generated writer lacks its reviewed native proof')
        seen.add(sha);result.append((Path(item['context']['path']),context,ranks.get(sha,item['order'])))
    return result


def baseline_context(root,knowledge):
    registry=load('native-release-registry').read(knowledge);found=[]
    for path in load('function-reuse-plan').context_files(knowledge,registry):
        context=json.loads(path.read_text('utf-8'));version,family=load('native-release-registry').context_identity(path,context,registry)
        if family=='string-writer':
            rank=next(r['order'] for r in registry['releases'] if r['id']==version);found.append((path,context,rank))
    found.extend(published_contexts(root,registry))
    if not found:raise ValueError('No reviewed string-writer baseline')
    return max(found,key=lambda v:(v[2],str(v[0])))[:2]


def plan_inputs(index,args,sha):
    """Use selected content identities, never self-changing mutable index bytes."""
    registry=load('native-release-registry').read(args.knowledge)
    common=load('update-native-contexts')
    baselines={str(path):index.digest(path) for path in (Path(args.knowledge)/'native-contexts').glob('string-writer-*.json')}
    selected=baseline_context(args.root,args.knowledge)
    baselines[str(selected[0])]=index.digest(selected[0])
    exports={str(Path(args.root)/'ghidra/request-exports'/selected[1]['source_sha256']/run/'details.json'):expected
        for run,expected in selected[1]['exports'].items()}
    for filename in exports:exports[filename]=index.digest(Path(filename))
    def relevant(folder,predicate):
        path=Path(args.root)/'knowledge'/folder/'index.json'
        if not path.is_file():return []
        result=[]
        for row in json.loads(path.read_text('utf-8'))['contexts']:
            context=checked(args.root,row['context'],'generated-native-contexts')
            if predicate(row,context):
                checked(args.root,row['check'],'native-adapter-checks');result.append(row)
        return result
    return dict(source=sha,tools=tools(),registry=index.digest(Path(args.knowledge)/'native-release-registry.json'),
        baselines=baselines,baseline_exports=exports,
        utf8=relevant('generated-native',lambda row,ctx:ctx['source_sha256']==sha),
        writer=relevant('generated-string-writers',lambda row,ctx:ctx['source_sha256']==sha or Path(row['context']['path'])==selected[0]))


def export_coverage(root,context,native,bindings,image):
    exports={};common=load('update-native-contexts')
    for run,expected in context['exports'].items():
        if Path(run).name!=run or not run.startswith('run-'):raise ValueError('Invalid writer export name')
        path=Path(root)/'ghidra/request-exports'/context['source_sha256']/run/'details.json'
        if common.digest(path)!=expected:raise ValueError('Writer export changed')
        report=json.loads(path.read_text('utf-8'))
        if report.get('new_source_sha256',report.get('source_sha256'))!=context['source_sha256']:
            raise ValueError('Writer export source differs')
        exports[str(path)]=dict(report=report,sha256=expected)
    catalog=load('function-reuse-plan')
    for key in ('length','convert','string-writer'):
        at=context['bindings'][key]
        if not catalog.export_covers(dict(address=at,exports=set(exports)),bindings.rows(native,image,int(at,16)),exports):
            raise ValueError('Writer export coverage missing: '+key)


def discover(index,args,sha):
    """Pure transfer plan; the coordinator collects only the three explicit roots."""
    common=load('update-native-contexts');registry=load('native-release-registry').read(args.knowledge)
    existing=[context for _,context,_ in published_contexts(args.root,registry) if context['source_sha256']==sha]
    if existing:
        context=existing[0];validate(index,args,context)
        proof=checked(args.root,context['transfer_proof'],'native-string-writer-proofs')
        return planned(context,proof)
    utf8=[(p,c,r) for p,c,r in load('native-release-registry').generated_contexts(args.root,registry)
        if c['source_sha256']==sha and c['family']=='utf8']
    if len(utf8)!=1:raise ValueError('A reviewed target UTF-8 context is required before writer transfer')
    utf8_path,current,_=utf8[0]
    common.admitted_instructions(current,args.root,{int(current['bindings'][k],16) for k in ('length','convert')},
        {int(current['bindings']['encoder'],16):current['encoder_leaf']['bytes']},source_store=args.source_store)
    baseline_path,baseline=baseline_context(args.root,args.knowledge)
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,sha)
    export_coverage(args.root,baseline,native,bindings,before)
    if baseline.get('transfer_proof'):validate(index,args,baseline)
    old_at=int(baseline['bindings']['string-writer'],16);new_at=int(current['bindings']['string-writer'],16)
    old_rows=bindings.rows(native,before,old_at);new_rows=bindings.rows(native,after,new_at)
    if common.signature(native,old_rows)!=common.signature(native,new_rows):raise ValueError('Whole writer instruction shape changed')
    old_fields=describe(native,bindings,before,old_at,baseline)
    if any(baseline[k]!=old_fields[k] for k in ('fixtures','writer_metadata')):
        raise ValueError('Reviewed writer baseline layout/call roles differ')
    fields=describe(native,bindings,after,new_at,current)
    if fields['calls']!=old_fields['calls']:raise ValueError('Writer call offsets/roles changed')
    context=dict(schema=1,source_sha256=sha,source=current['source'],family='string-writer',
        bindings=current['bindings'],encoder_leaf=current['encoder_leaf'],helpers=current['helpers'],
        fixtures=fields['fixtures'],writer_metadata=fields['writer_metadata'],verify_whole_exports=True,layout=LAYOUT)
    proof=common.receipt(args.root,'native-string-writer-proofs',dict(schema=1,adapter=ADAPTER,scope=SCOPE,
        baseline=dict(path=str(baseline_path),sha256=common.digest(baseline_path)),
        utf8=dict(path=str(utf8_path),sha256=common.digest(utf8_path)),target=context,
        relocated_inputs=fields['inputs'],calls=fields['calls'],tools=tools(),runtime_activated=False))
    context=dict(context,transfer_proof=proof)
    return planned(context,checked(args.root,proof,'native-string-writer-proofs'))


def planned(context,proof):
    context={k:v for k,v in context.items() if k!='exports'}
    return dict(state='planned',source_sha256=context['source_sha256'],context=context,
        exports=sorted({context['bindings'][k] for k in ('length','convert','string-writer')},key=lambda x:int(x,16)),
        dependencies=tools(),artifacts={proof['baseline']['path']:proof['baseline']['sha256'],
            proof['utf8']['path']:proof['utf8']['sha256'],context['transfer_proof']['path']:context['transfer_proof']['sha256']})


def validate(index,args,context,seen=None):
    """Recheck the proof against PE bytes; never trust a modified receipt's claims."""
    common=load('update-native-contexts');proof=checked(args.root,context['transfer_proof'],'native-string-writer-proofs')
    seen=set(seen or ());identity=context['transfer_proof']['sha256']
    if identity in seen or len(seen)>=32:raise ValueError('Writer proof cycle/depth budget exceeded')
    seen.add(identity)
    if (proof.get('schema')!=1 or proof.get('adapter')!=ADAPTER or proof.get('scope')!=SCOPE or proof.get('tools')!=tools()
            or proof.get('runtime_activated') is not False or context.get('layout')!=LAYOUT
            or proof.get('target')!={k:v for k,v in context.items() if k not in ('exports','transfer_proof','release_id')}):
        raise ValueError('Writer proof fields, tools or layout differ')
    path=Path(proof['baseline']['path']).resolve()
    if not (path.is_relative_to((HERE/'knowledge/native-contexts').resolve())
            or path.is_relative_to((Path(args.root)/'knowledge/generated-native-contexts').resolve())):
        raise ValueError('Writer baseline outside reviewed contexts')
    if common.digest(path)!=proof['baseline']['sha256']:raise ValueError('Writer baseline changed')
    baseline=json.loads(path.read_text('utf-8'))
    if baseline.get('transfer_proof'):validate(index,args,baseline,seen)
    utf8=checked(args.root,proof['utf8'],'generated-native-contexts')
    common.admitted_instructions(utf8,args.root,{int(utf8['bindings'][k],16) for k in ('length','convert')},
        {int(utf8['bindings']['encoder'],16):utf8['encoder_leaf']['bytes']},source_store=args.source_store)
    if utf8['source_sha256']!=context['source_sha256']:raise ValueError('Writer target UTF-8 source differs')
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,context['source_sha256'])
    export_coverage(args.root,baseline,native,bindings,before)
    old=int(baseline['bindings']['string-writer'],16);new=int(context['bindings']['string-writer'],16)
    if common.signature(native,bindings.rows(native,before,old))!=common.signature(native,bindings.rows(native,after,new)):
        raise ValueError('Whole writer instruction shape changed')
    fields=describe(native,bindings,after,new,utf8);old_fields=describe(native,bindings,before,old,baseline)
    if any(baseline[k]!=old_fields[k] for k in ('fixtures','writer_metadata')):
        raise ValueError('Reviewed writer baseline layout/call roles differ')
    if (context['bindings']!=utf8['bindings'] or context['helpers']!=utf8['helpers']
            or context['encoder_leaf']!=utf8['encoder_leaf'] or context['source']!=utf8['source']
            or fields['calls']!=old_fields['calls'] or proof['calls']!=fields['calls']
            or proof['relocated_inputs']!=fields['inputs']
            or any(context[k]!=fields[k] for k in ('fixtures','writer_metadata'))):
        raise ValueError('Writer relocated data, calls or typed context differ')
    return context


def materialize(index,args,sha,plan,database):
    if plan.get('state')!='planned':return dict(checks=[],queue=[dict(family='string-writer',reason='native_adapter_requires_review',details=plan.get('reason'))])
    context=copy.deepcopy(plan['context']);workflow=load('research-workflow');db=index.open_index(database);exports={}
    try:
        for at in plan['exports']:
            state=workflow.function_state(index,db,sha,at)
            if state['state']!='ready':raise ValueError('Writer target export is not ready: '+at)
            for row in state['variants']:
                if not row['completed']:continue
                path=Path(row['artifact']).resolve()
                parent=(Path(args.root)/'ghidra/request-exports'/sha).resolve()
                if path.is_relative_to(parent) and path.name=='details.json':exports[path.parent.name]=index.digest(path)
    finally:db.close()
    context['exports']=exports;validate(index,args,context)
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    export_coverage(args.root,context,native,bindings,args.source_store.image(native,sha))
    target=load('update-native-contexts').receipt(args.root,'generated-native-contexts',context)
    artifacts={**plan['artifacts'],target['path']:target['sha256']}
    artifacts.update({str(Path(args.root)/'ghidra/request-exports'/sha/run/'details.json'):expected for run,expected in exports.items()})
    declaration=dict(id='native-auto-string-writer',adapter=ADAPTER,scope=SCOPE,contracts=[],context=target,
        proof=context['transfer_proof'],dependencies=tools(),artifacts=artifacts)
    return dict(checks=[declaration],queue=[])


def execute(index,args,sha,declaration):
    context=checked(args.root,declaration['context'],'generated-native-contexts')
    if (declaration.get('adapter')!=ADAPTER or declaration.get('scope')!=SCOPE
            or context['source_sha256']!=sha or declaration['dependencies']!=tools()):raise ValueError('Writer check declaration differs')
    for filename,expected in declaration['artifacts'].items():
        if index.digest(filename)!=expected:raise ValueError('Writer check artifact changed')
    validate(index,args,context)
    report=load('verify-string-writer-context').verify(context,args.root)
    report.update(scope=SCOPE,proof=context['transfer_proof'],runtime_activated=False,context_sha256=declaration['context']['sha256'])
    target=load('update-native-contexts').receipt(args.root,'native-adapter-checks',report)
    return dict(id=declaration['id'],state='passed',report=target['path'],sha256=target['sha256'],
        scope=SCOPE,runtime_activated=False,profile_activated=False)


def publish(index,args,sha,declaration,outcome):
    if outcome.get('state')!='passed':raise ValueError('Only a passed writer can be published')
    context=checked(args.root,declaration['context'],'generated-native-contexts');validate(index,args,context)
    check=dict(path=outcome['report'],sha256=outcome['sha256']);report=checked(args.root,check,'native-adapter-checks')
    if report.get('context_sha256')!=declaration['context']['sha256'] or context['source_sha256']!=sha:
        raise ValueError('Writer publication context differs')
    registry=load('native-release-registry').read(args.knowledge);published_contexts(args.root,registry)
    path=Path(args.root)/'knowledge/generated-string-writers/index.json'
    old=json.loads(path.read_text('utf-8')) if path.is_file() else dict(schema=1,contexts=[])
    entries=[r for r in old['contexts'] if checked(args.root,r['context'],'generated-native-contexts')['source_sha256']!=sha]
    ranks={r['source_sha256']:r['order'] for r in registry['releases']}
    rank=ranks.get(sha,max([r['order'] for r in registry['releases']]+[r['order'] for r in entries])+1)
    entries.append(dict(context=declaration['context'],check=check,order=rank))
    value=dict(schema=1,contexts=sorted(entries,key=lambda r:(r['order'],r['context']['path'])))
    published_contexts(args.root,registry,value=value)
    workflow=load('research-workflow');workflow.atomic(path,workflow.canonical(value))
    return dict(path=str(path),sha256=index.digest(path))
