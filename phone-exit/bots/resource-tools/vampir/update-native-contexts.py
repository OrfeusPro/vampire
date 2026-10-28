"""Reviewed typed native adapters for arbitrary target SHAs, never runtime admission.

Only UTF-8 helpers are currently portable. Other native families stay explicit
blockers; a new SHA is not added to a legacy suite's source whitelist.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
TOOLS=('update-native-contexts.py','native-release-registry.py','verify-utf8-context.py',
       'update-native-harness.py','update-bindings.py','build-native-entry-code.py',
       'build-object-zero-init-code.py','extract-native-enums.py','research-workflow.py')
LAYOUT=dict(abi='win64',input_encoding='utf16le',output_encoding='utf8',
            length_unit='utf16_code_units',max_output_bytes=1024,encoder_leaf_max_bytes=512)
LIMITS=['Native UTF-8 length/conversion/scalar only; string writer links are static.',
        'No whole writer/archive, preparation, OS, network, authorization or runtime admission.']


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def receipt(root,category,value):
    path=load('research-workflow').snapshot(root,category,value)
    return dict(path=str(path),sha256=digest(path))


def checked(root,item,category):
    path=Path(item['path']).resolve();folder=(Path(root)/'knowledge'/category).resolve()
    if (not path.is_relative_to(folder) or path.name!='manifest.json'
            or path.parent.name!=item['sha256'] or digest(path)!=item['sha256']):
        raise ValueError('Native adapter receipt changed: '+category)
    return json.loads(path.read_text('utf-8'))


def image_bytes(image,at,size):
    off=image.offset(at-image.pe.base);value=image.data[off:off+size]
    if len(value)!=size:raise ValueError('Native adapter data bounds differ')
    return value


def recipe_for(native,bindings,image,at,key,*,callee=None):
    rows=bindings.rows(native,image,at);locations={row['address'] for row in rows};calls={}
    for row in rows:
        if row['rip_references']:raise ValueError('UTF-8 helper has undeclared static data')
        if row['call'] or row['branch']:
            target=row['direct_target']
            if target in locations:continue
            if not row['call'] or callee is None or target!=callee:
                raise ValueError('UTF-8 helper has an unreviewed external dependency')
            calls[str(row['address']-at)]='encoder'
    if callee is not None and len(calls)!=2:raise ValueError('UTF-8 conversion callee count differs')
    return dict(key=key,baseline_address=hex(at),calls=calls,data={},search_window=65536,method='closed_shape')


def leaf_valid(native,image,at,leaf):
    raw=bytes.fromhex(leaf['bytes'])
    if (leaf['size']!=len(raw) or not 1<=len(raw)<=512
            or hashlib.sha256(raw).hexdigest()!=leaf['sha256'] or image_bytes(image,at,len(raw))!=raw):
        raise ValueError('UTF-8 encoder leaf bytes or layout differ')
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    rows=list(decoder.disasm(raw,at));locations={row.address for row in rows}
    if sum(row.size for row in rows)!=len(raw) or not rows or rows[-1].mnemonic!='ret':
        raise ValueError('UTF-8 leaf instruction boundary differs')
    for row in rows:
        if row.group(native.capstone.CS_GRP_CALL):raise ValueError('UTF-8 encoder leaf calls are not reviewed')
        if any(op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP for op in row.operands):
            raise ValueError('UTF-8 encoder leaf static data is not reviewed')
        if row.group(native.capstone.CS_GRP_JUMP) and (len(row.operands)!=1
                or row.operands[0].type!=native.X86_OP_IMM or row.operands[0].imm not in locations):
            raise ValueError('UTF-8 encoder leaf external branch is not reviewed')
    return raw


def signature(native,rows):
    """Candidate provider only; writer semantics are not inferred from this mask."""
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    origin=rows[0]['address'];locations={row['address'] for row in rows};result=[]
    for row in rows:
        raw=bytearray.fromhex(row['bytes']);ins=next(decoder.disasm(bytes(raw),row['address']))
        local=None
        if row['call'] or row['branch']:
            if row['direct_target'] in locations:local=row['direct_target']-origin
            if row['direct_target'] is not None:raw[ins.imm_offset:ins.imm_offset+ins.imm_size]=bytes(ins.imm_size)
        if row['rip_references']:raw[ins.disp_offset:ins.disp_offset+ins.disp_size]=bytes(ins.disp_size)
        result.append((row['address']-origin,raw.hex(),local))
    return result


def memcpy_identity(native,image,at):
    if image_bytes(image,at,2)!=b'\xff\x25':raise ValueError('UTF-8 helper is not an import thunk')
    raw=image_bytes(image,at,6);slot=at+6+struct.unpack_from('<i',raw,2)[0]
    found=load('build-object-zero-init-code').import_at(image.data,image,slot)
    if (found['dll'].lower(),found['name'])!=('vcruntime140.dll','memcpy'):
        raise ValueError('UTF-8 memcpy import identity differs')


def find_memcpy(native,old,new,at):
    memcpy_identity(native,old,at)
    try:memcpy_identity(native,new,at);return at
    except (ValueError,KeyError,struct.error):pass
    # Restrict discovery to the reviewed thunk neighbourhood, never arbitrary IAT.
    result=[]
    for candidate in range(max(new.pe.base,at-65536),at+65536):
        try:
            if image_bytes(new,candidate,2)!=b'\xff\x25':continue
            memcpy_identity(native,new,candidate);result.append(candidate)
        except (ValueError,KeyError,struct.error):continue
    if len(result)!=1:raise ValueError('Missing or ambiguous UTF-8 memcpy import')
    return result[0]


def baseline_context(root,knowledge,registry,spec):
    api=load('native-release-registry');order={row['id']:row['order'] for row in registry['releases']}
    found=[]
    for path in load('function-reuse-plan').context_files(knowledge,registry):
        context=json.loads(path.read_text('utf-8'));version,family=api.context_identity(path,context,registry)
        if family==spec['family']:found.append((order[version],path,context))
    # A generated reviewed context is preferred over older repository evidence.
    for path,context,rank in api.generated_contexts(root,registry):
        if context.get('family')==spec['family']:found.append((rank,path,context))
    if not found:raise ValueError('No reviewed baseline context for '+spec['family'])
    _,path,context=max(found,key=lambda item:(item[0],str(item[1])))
    return path,context


def validate_baseline(root,context,native,bindings,image,*,source_store=None,seen=None):
    if (set(context['bindings'])!={'length','convert','encoder','string-writer'}
            or set(context.get('helpers',{}))!={'memcpy'}):
        raise ValueError('UTF-8 typed context fields differ')
    if context.get('native_admission'):
        admitted_instructions(context,root,{int(context['bindings'][key],16) for key in ('length','convert')},
            {int(context['bindings']['encoder'],16):context['encoder_leaf']['bytes']},source_store=source_store,_seen=seen)
        return
    catalog=load('function-reuse-plan');exports={}
    for run,expected in context.get('exports',{}).items():
        if Path(run).name!=run or not run.startswith('run-'):raise ValueError('Invalid UTF-8 baseline export')
        path=Path(root)/'ghidra/request-exports'/context['source_sha256']/run/'details.json'
        if digest(path)!=expected:raise ValueError('UTF-8 baseline export changed')
        report=json.loads(path.read_text('utf-8'))
        if report.get('new_source_sha256',report.get('source_sha256'))!=context['source_sha256']:
            raise ValueError('UTF-8 baseline export source differs')
        exports[str(path)]=dict(report=report,sha256=expected)
    for key in ('length','convert','string-writer'):
        at=context['bindings'][key]
        if not catalog.export_covers(dict(address=at,exports=set(exports)),bindings.rows(native,image,int(at,16)),exports):
            raise ValueError('UTF-8 baseline export does not cover '+key)


def discover_utf8(index,args,sha,baseline_path,baseline):
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    store=getattr(args,'source_store',None) or bindings.SourceStore(index,args.root)
    before=store.image(native,baseline['source_sha256']);after=store.image(native,sha)
    validate_baseline(args.root,baseline,native,bindings,before,source_store=store)
    old={key:int(at,16) for key,at in baseline['bindings'].items()}
    leaf_valid(native,before,old['encoder'],baseline['encoder_leaf'])
    length=recipe_for(native,bindings,before,old['length'],'length')
    convert=recipe_for(native,bindings,before,old['convert'],'convert',callee=old['encoder'])
    length['baseline_sha256']=convert['baseline_sha256']=baseline['source_sha256']
    length_hits=bindings.shape_candidates(native,after,before,length,baseline['bindings'])
    if len(length_hits)!=1:raise ValueError('Missing or ambiguous closed UTF-8 length candidate')
    convert_hits=[]
    for at in bindings.shape_candidates(native,after,before,convert,baseline['bindings']):
        targets=[target for _,target in bindings.candidate_callees(native,after,int(at,16),convert)]
        if len(set(targets))!=1:continue
        try:leaf_valid(native,after,int(targets[0],16),baseline['encoder_leaf'])
        except ValueError:continue
        convert_hits.append((at,targets[0]))
    if len(convert_hits)!=1:raise ValueError('Missing or ambiguous closed UTF-8 conversion/encoder candidate')
    current=dict(length=length_hits[0],convert=convert_hits[0][0],encoder=convert_hits[0][1])
    old_rows=bindings.rows(native,before,old['string-writer']);expected=signature(native,old_rows)
    size=before.roots[before.containing(old['string-writer'])][1]-before.roots[before.containing(old['string-writer'])][0]
    candidates=[after.pe.base+row[0] for row in after.roots
        if abs(after.pe.base+row[0]-old['string-writer'])<=65536 and row[1]-row[0]==size]
    if len(candidates)>4096:raise ValueError('UTF-8 writer candidate budget exceeded')
    writers=[]
    for at in candidates:
        try:rows=bindings.rows(native,after,at)
        except ValueError:continue
        if signature(native,rows)!=expected:continue
        calls=[row['direct_target'] for row in rows if row['call']]
        if all(calls.count(int(current[key],16))==1 for key in ('length','convert')):writers.append(at)
    if len(writers)!=1:raise ValueError('Missing or ambiguous UTF-8 static writer linkage')
    current['string-writer']=hex(writers[0])
    helper=find_memcpy(native,before,after,int(baseline['helpers']['memcpy'],16))
    context=dict(schema=1,source_sha256=sha,source=str(Path(args.root)/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'),
        family='utf8',bindings=current,encoder_leaf=baseline['encoder_leaf'],helpers=dict(memcpy=hex(helper)),exports={},layout=LAYOUT)
    proof=dict(schema=1,adapter='utf8-v1',source_sha256=sha,baseline_sha256=baseline['source_sha256'],
        baseline=dict(path=str(baseline_path),sha256=digest(baseline_path)),target_context=context,
        recipes=[length,convert],layout=LAYOUT,tools={name:digest(HERE/name) for name in TOOLS},
        scope='bounded_native_utf8',runtime_activated=False,profile_activated=False,limits=LIMITS)
    proof_receipt=receipt(args.root,'native-context-proofs',proof)
    context=dict(context,native_admission=proof_receipt)
    # Validate every generated field before exposing a declaration to the runner.
    admitted_instructions(context,args.root,{int(current[key],16) for key in ('length','convert')},
        {int(current['encoder'],16):context['encoder_leaf']['bytes']},source_store=store)
    if getattr(args,'source_store',None) is None:store.validate()
    return context,proof_receipt


def admitted_instructions(context,root,functions,leaves,*,source_store=None,_seen=None):
    """Harness gate for this reviewed adapter; no arbitrary instructions/fixtures."""
    proof=checked(root,context['native_admission'],'native-context-proofs')
    seen=set(_seen or ())
    pointer=context['native_admission']['path']
    if pointer in seen or len(seen)>=64:raise ValueError('Native proof cycle/depth budget exceeded')
    seen.add(pointer)
    if (proof.get('schema')!=1 or proof.get('adapter')!='utf8-v1' or proof.get('layout')!=LAYOUT
            or proof.get('scope')!='bounded_native_utf8' or proof.get('runtime_activated') is not False
            or proof.get('profile_activated') is not False):raise ValueError('Unreviewed native adapter proof')
    plain={key:value for key,value in context.items() if key not in ('native_admission','release_id')}
    if proof['target_context']!=plain:raise ValueError('Native context differs from proved target fields/layout')
    if proof['tools']!={name:digest(HERE/name) for name in TOOLS}:raise ValueError('Native adapter tools changed')
    path=Path(proof['baseline']['path']).resolve()
    allowed=(HERE/'knowledge/native-contexts').resolve()
    generated=(Path(root)/'knowledge/generated-native-contexts').resolve()
    if not path.is_relative_to(allowed) and not path.is_relative_to(generated):
        raise ValueError('Native adapter baseline outside reviewed contexts')
    if digest(path)!=proof['baseline']['sha256']:raise ValueError('Native adapter baseline changed')
    baseline=json.loads(path.read_text('utf-8'))
    if baseline['source_sha256']!=proof['baseline_sha256']:raise ValueError('Native adapter baseline source differs')
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    store=source_store or bindings.SourceStore(load('knowledge-index').api(),root)
    before=store.image(native,proof['baseline_sha256']);after=store.image(native,context['source_sha256'])
    if context['source_sha256']!=proof['source_sha256']:raise ValueError('Native adapter target source differs')
    current={key:int(at,16) for key,at in context['bindings'].items()}
    if (functions!={current['length'],current['convert']}
            or leaves!={current['encoder']:context['encoder_leaf']['bytes']}
            or context['layout']!=LAYOUT):raise ValueError('Native adapter execution scope differs')
    validate_baseline(root,baseline,native,bindings,before,source_store=store,seen=seen)
    leaf_valid(native,before,int(baseline['bindings']['encoder'],16),baseline['encoder_leaf'])
    leaf_valid(native,after,current['encoder'],context['encoder_leaf'])
    if context['encoder_leaf']!=baseline['encoder_leaf']:raise ValueError('UTF-8 leaf declaration changed')
    declared={row['key']:row for row in proof['recipes']}
    expected={key:recipe_for(native,bindings,before,int(baseline['bindings'][key],16),key,
        callee=int(baseline['bindings']['encoder'],16) if key=='convert' else None) for key in ('length','convert')}
    for key,row in expected.items():row['baseline_sha256']=baseline['source_sha256']
    if declared!=expected:raise ValueError('Native adapter closure recipe changed')
    rows=[]
    for key,row in expected.items():
        if bindings.closed_shape(native,before,int(baseline['bindings'][key],16),baseline['bindings'],row)!=bindings.closed_shape(native,after,current[key],context['bindings'],row):
            raise ValueError('Native adapter helper closure changed')
        rows.append(dict(address=context['bindings'][key],instructions=[dict(address=hex(r['address']),bytes=r['bytes'])
            for r in bindings.rows(native,after,current[key])]))
    old_writer=bindings.rows(native,before,int(baseline['bindings']['string-writer'],16))
    new_writer=bindings.rows(native,after,current['string-writer'])
    if signature(native,old_writer)!=signature(native,new_writer):raise ValueError('UTF-8 static writer candidate changed')
    calls=[row['direct_target'] for row in new_writer if row['call']]
    if any(calls.count(current[key])!=1 for key in ('length','convert')):
        raise ValueError('UTF-8 static writer links changed')
    memcpy_identity(native,after,int(context['helpers']['memcpy'],16))
    if source_store is None:store.validate()
    return dict(functions=rows,evidence=[context['native_admission']],source_sha256=context['source_sha256'])


def materialize(index,args,sha,contexts,function_reuse):
    api=load('native-release-registry');registry=api.read(args.knowledge)
    result=dict(schema=1,source_sha256=sha,declarations=[],checks=[],queue=[],runtime_activated=False,profile_activated=False)
    known={spec['family']:spec for spec in registry['suite_adapters']}
    families=set()
    for path in load('function-reuse-plan').context_files(args.knowledge,registry):
        context=json.loads(path.read_text('utf-8'));_,family=api.context_identity(path,context,registry)
        families.add(family)
    result['family_coverage']=[dict(family=family,adapter=known.get(family,{}).get('adapter','unsupported'),
        reason=known.get(family,{}).get('reason','Нет проверенного общего адаптера этого семейства.')) for family in sorted(families)]
    unregistered=sorted(families-set(known))
    if unregistered:result['queue'].append(dict(families=unregistered,reason='unregistered_native_suite_families',
        details='Семейства видны в каталоге, но не имеют проверенного semantic adapter.'))
    for spec in registry['suite_adapters']:
        if spec['adapter']=='unsupported':
            result['queue'].append(dict(family=spec['family'],reason='unsupported_native_adapter',details=spec['reason']));continue
        try:
            path,baseline=baseline_context(args.root,args.knowledge,registry,spec)
            if baseline['source_sha256']==sha and baseline.get('native_admission'):
                context,proof=baseline,baseline['native_admission']
            else:context,proof=discover_utf8(index,args,sha,path,baseline)
            target=receipt(args.root,'generated-native-contexts',context)
            origin=checked(args.root,proof,'native-context-proofs')['baseline']
            declaration=dict(id='native-auto-utf8',adapter='utf8-v1',context=target,proof=proof,contracts=[],
                scope='bounded_native_utf8',dependencies={str(HERE/name):digest(HERE/name) for name in TOOLS},
                artifacts={origin['path']:origin['sha256'],proof['path']:proof['sha256'],target['path']:target['sha256']})
            result['declarations'].append(declaration);result['checks'].append(declaration)
        except (ValueError,OSError,KeyError,StopIteration,struct.error) as error:
            result['queue'].append(dict(family=spec['family'],reason='native_adapter_requires_review',details=str(error)))
    generated=Path(args.root)/'knowledge/generated-native/index.json'
    result['generated_index']=dict(path=str(generated),sha256=digest(generated)) if generated.is_file() else None
    return result


def execute(index,args,sha,declaration):
    if declaration.get('adapter')!='utf8-v1' or declaration.get('scope')!='bounded_native_utf8':
        raise ValueError('Unreviewed generated native check')
    context=checked(args.root,declaration['context'],'generated-native-contexts')
    if context['source_sha256']!=sha:raise ValueError('Generated native check source differs')
    if declaration['dependencies']!={str(HERE/name):digest(HERE/name) for name in TOOLS}:
        raise ValueError('Generated native check dependencies changed')
    for path,expected in declaration['artifacts'].items():
        if digest(path)!=expected:raise ValueError('Generated native check artifact changed')
    report=load('verify-utf8-context').verify(context,args.root)
    report.update(scope='bounded_native_utf8',runtime_activated=False,proof=declaration['proof'])
    target=receipt(args.root,'native-adapter-checks',report)
    return dict(id=declaration['id'],state='passed',report=target['path'],sha256=target['sha256'],
        scope='bounded_native_utf8',runtime_activated=False,profile_activated=False)


def publish(index,args,sha,declaration,outcome):
    """Restore an index pointer after a cached success, without replaying native."""
    if outcome.get('state')!='passed' or declaration.get('adapter')!='utf8-v1':
        raise ValueError('Only a passed reviewed native adapter can be published')
    context=checked(args.root,declaration['context'],'generated-native-contexts')
    check=dict(path=outcome['report'],sha256=outcome['sha256'])
    report=checked(args.root,check,'native-adapter-checks')
    if (context['source_sha256']!=sha or report.get('source_sha256')!=sha
            or report.get('bindings')!=context['bindings'] or report.get('proof')!=context['native_admission']):
        raise ValueError('Native publication source/context differs')
    admitted_instructions(context,args.root,{int(context['bindings'][key],16) for key in ('length','convert')},
        {int(context['bindings']['encoder'],16):context['encoder_leaf']['bytes']},source_store=getattr(args,'source_store',None))
    return load('native-release-registry').publish_generated(args.root,context,declaration['context'],check)


def operational_model(index,args,model):
    """Use a published closed helper as a future baseline; never promote its writer."""
    registry=load('native-release-registry').read(args.knowledge)
    generated=load('native-release-registry').generated_contexts(args.root,registry)
    if not generated:return model
    revised=copy.deepcopy(model)
    contract=next((c for c in revised['contracts'] if c['id']=='game-version'),None)
    if contract is None:return model
    recipe=next((r for r in contract['recipes'] if r['key']=='utf8-length' and r['method']=='closed_shape'),None)
    if recipe is None:return model
    order={row['source_sha256']:row['order'] for row in registry['releases']}
    rank=order.get(recipe['baseline_sha256'],-1)
    candidates=sorted((item for item in generated if item[1].get('family')=='utf8' and item[2]>rank),
        key=lambda item:(item[2],str(item[0])))
    if not candidates:return model
    _,context,_=candidates[-1]
    # An invalid newest declaration fails closed. Do not fall back to older proof.
    admitted_instructions(context,args.root,{int(context['bindings'][k],16) for k in ('length','convert')},
        {int(context['bindings']['encoder'],16):context['encoder_leaf']['bytes']},
        source_store=getattr(args,'source_store',None))
    sha=context['source_sha256'];at=context['bindings']['length']
    contract['bindings'].setdefault(sha,{})['utf8-length']=at
    recipe.update(baseline_sha256=sha,baseline_address=at,calls={},data={})
    return revised
