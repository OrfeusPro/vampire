"""Ordered static INPUT mappings for quest/tutorial research, without admission."""
import copy
import hashlib
import json
from pathlib import Path
import re


HERE=Path(__file__).resolve().parent
RECIPE='quest-input-seed-v2'
STAGE='native-input-seed-quest-tutorial-v2'
CATEGORY='quest-input-seed-proofs-v2'
LIMIT=32*1024*1024
SHA=re.compile('[0-9a-f]{64}')
ADDRESS=re.compile('0x[0-9a-f]+')
ROLE_MAP={
    'input_constructor':'constructor','input_buffer_constructor':'buffer_constructor',
    'input_u16':'u16','input_u32':'u32','input_u64':'u64','input_bool':'bool','input_raw':'raw'}
COMMON=set(ROLE_MAP)|{'vector','reader'}
CONSUMER_ROLES={
    'quest-sync':COMMON|{'packet_constructor','nested_reader','group_reader','quest_reader',
        'progress_reader','group_callback','quest_callback','group_reserve','quest_reserve'},
    'tutorial-update':COMMON|{'packet_constructor','nested_reader','item_reader','callback'}}
LIMITS=[
    'Seven primitive/buffer mappings are static projections of a separately checked VersionResult input closure.',
    'Consumer packet constructors/readers, vector loop, callbacks and storage effects have not been transferred or executed.',
    'No consumer semantic check, runtime source allowlist, profile, live session or gameplay action is changed.']


def exact_pointer(value):
    return (isinstance(value,dict) and set(value)=={'path','sha256'}
        and isinstance(value['path'],str) and Path(value['path']).is_absolute()
        and isinstance(value['sha256'],str) and SHA.fullmatch(value['sha256']) is not None)


def pointer_document(index,pointer,folder):
    if not exact_pointer(pointer):raise ValueError('Quest input seed needs an exact absolute pointer')
    path=Path(pointer['path']).resolve()
    if not path.is_relative_to(Path(folder).resolve()):raise ValueError('Quest input seed pointer escapes its knowledge scope')
    with path.open('rb') as stream:raw=stream.read(LIMIT+1)
    if len(raw)>LIMIT or hashlib.sha256(raw).hexdigest()!=pointer['sha256']:
        raise ValueError('Quest input seed pointer changed or exceeds budget')
    value=json.loads(raw.decode('utf-8-sig'))
    if not isinstance(value,dict):raise ValueError('Quest input seed document must be an object')
    return value


def configuration(index,args):
    path=Path(args.knowledge)/'quest-input-seed.json'
    if not path.is_file():return None
    with path.open('rb') as stream:raw=stream.read(16385)
    value=json.loads(raw)
    if (len(raw)>16384 or not isinstance(value,dict)
            or set(value)!={'schema','recipe','version_baseline','consumers'}
            or type(value['schema']) is not int or value['schema']!=1 or value['recipe']!=RECIPE
            or not isinstance(value['consumers'],dict) or set(value['consumers'])!=set(CONSUMER_ROLES)):
        raise ValueError('Unknown quest input seed rule')
    folder=(Path(index.HERE)/'knowledge/native-contexts').resolve()
    pointers=[value['version_baseline'],*value['consumers'].values()]
    for pointer in pointers:
        if (not exact_pointer(pointer) or not Path(pointer['path']).resolve().is_relative_to(folder)
                or Path(pointer['path']).suffix!='.json'):
            raise ValueError('Quest input seed baseline must be inside repository native knowledge')
    if len({str(Path(p['path']).resolve()) for p in pointers})!=3:
        raise ValueError('Quest input seed baseline pointers alias')
    return value


def inventory(consumers,version_baseline):
    sha=version_baseline.get('source_sha256')
    if not isinstance(sha,str) or not SHA.fullmatch(sha):raise ValueError('Quest input seed baseline needs a full source SHA')
    primitives=(version_baseline.get('native_input') or {}).get('functions')
    if not isinstance(primitives,dict) or not set(ROLE_MAP.values())<=set(primitives):
        raise ValueError('Quest input seed VersionResult roles are missing')
    roots={};by_consumer={}
    for name,roles in CONSUMER_ROLES.items():
        context=consumers[name];functions=context.get('functions')
        if (context.get('source_sha256')!=sha or not isinstance(functions,dict) or set(functions)!=roles
                or any(not isinstance(a,str) or not ADDRESS.fullmatch(a) for a in functions.values())
                or len(set(functions.values()))!=len(functions)):
            raise ValueError('Quest input seed consumer source or root scope differs: '+name)
        by_consumer[name]=set(functions.values())
        for role,address in functions.items():roots.setdefault(address,[]).append(dict(consumer=name,role=role))
        for old_role,input_role in ROLE_MAP.items():
            if functions[old_role]!=primitives[input_role]:
                raise ValueError('Quest input seed consumer primitive differs from VersionResult: '+name+'/'+old_role)
    shared=by_consumer['quest-sync']&by_consumer['tutorial-update']
    mapped={primitives[role] for role in ROLE_MAP.values()}
    if len(roots)!=22 or len(shared)!=9 or len(mapped)!=7 or not mapped<=shared:
        raise ValueError('Quest input seed shared/unique root inventory differs')
    for role in COMMON:
        if consumers['quest-sync']['functions'][role]!=consumers['tutorial-update']['functions'][role]:
            raise ValueError('Quest input seed common role identity differs')
    return dict(source_sha256=sha,unique_roots=22,shared_roots=9,mapped_roots=7,pending_roots=15,
        roots=[dict(address=at,roles=sorted(roles,key=lambda r:(r['consumer'],r['role'])),
            shared=at in shared,state='input_seed' if at in mapped else 'pending_consumer_transfer')
            for at,roles in sorted(roots.items(),key=lambda item:int(item[0],16))])


def unavailable(reason):
    return dict(state='requires_review',recipe=RECIPE,method='static',reason=reason,
        native_consumer_verified=False,runtime_activated=False,profile_activated=False,limits=LIMITS)


def validate_relation(relation,mappings):
    if not isinstance(relation,dict) or not isinstance(relation.get('mapping'),dict) or len(relation['mapping'])>32768:
        raise ValueError('Quest input seed supporting transfer relation differs')
    for before,after in relation['mapping'].items():
        if (not isinstance(before,str) or not ADDRESS.fullmatch(before)
                or not isinstance(after,str) or not ADDRESS.fullmatch(after)):
            raise ValueError('Quest input seed supporting relocation needs exact addresses')
    if any(relation['mapping'].get(r['baseline'])!=r['target'] for r in mappings):
        raise ValueError('Quest input seed supporting relation differs from seven input roles')


def run(index,args,sha,journal,native_contexts,native_checks):
    rule=configuration(index,args)
    if rule is None:return dict(state='disabled',recipe=RECIPE,runtime_activated=False,profile_activated=False)
    if not isinstance(sha,str) or not SHA.fullmatch(sha):raise ValueError('Quest input seed target needs a full source SHA')
    if not hasattr(args,'source_store'):raise ValueError('Quest input seed requires the frozen source store')
    declarations=[d for d in native_contexts.get('checks',[]) if d.get('id')=='native-auto-version-result']
    outcomes=[c for c in native_checks if c.get('id')=='native-auto-version-result']
    if len(declarations)!=1:return unavailable('version_result_target_declaration_missing_or_ambiguous')
    if len(outcomes)!=1 or outcomes[0].get('state')!='passed':
        return unavailable('version_result_target_semantic_check_missing_or_ambiguous')
    declaration,outcome=declarations[0],outcomes[0]
    api=index.extension('update-native-version-result');core=index.extension('portable-native-family')
    workflow=index.extension('research-workflow')
    tools=copy.deepcopy(api.tools())
    for path in (Path(__file__),HERE/'portable-native-family.py',HERE/'stage-action-tools-v1.py',
            HERE/'native-publication-v2.py'):
        tools[str(path.resolve())]=index.digest(path)
    if (declaration.get('adapter')!='version-result-v1' or declaration.get('scope')!=api.SCOPE
            or declaration.get('dependencies')!=api.tools() or outcome.get('scope')!=api.SCOPE
            or outcome.get('runtime_activated') is not False or outcome.get('profile_activated') is not False):
        return unavailable('version_result_target_declaration_or_scope_differs')
    target_pointer=declaration.get('context');check_pointer=dict(path=outcome.get('report'),sha256=outcome.get('sha256'))
    try:
        for p in (target_pointer,check_pointer):
            if not exact_pointer(p) or Path(p['path']).name!='manifest.json' or Path(p['path']).parent.name!=p['sha256']:
                raise ValueError('Quest input seed target needs immutable proof pointers')
        target=pointer_document(index,target_pointer,Path(args.root)/'knowledge/generated-native-contexts')
        report=pointer_document(index,check_pointer,Path(args.root)/'knowledge/native-adapter-checks')
        if (target.get('source_sha256')!=sha or target.get('family')!='version-result'
                or declaration.get('proof')!=target.get('transfer_proof')):
            raise ValueError('Quest input seed target source/proof differs')
        api.report_valid(report,target,target_pointer['sha256'])
        folder=Path(index.HERE)/'knowledge/native-contexts'
        baseline=pointer_document(index,rule['version_baseline'],folder)
        consumers={name:pointer_document(index,p,folder) for name,p in rule['consumers'].items()}
        roots=inventory(consumers,baseline)
        if roots['source_sha256']==sha:return unavailable('quest_input_seed_requires_ordered_distinct_sources')
        expected_source=Path(args.root)/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
        expected_old=Path(args.root)/'client-code-snapshots'/roots['source_sha256']/'ProjectRED-Win64-Shipping.exe'
        if Path(target.get('source','')).resolve()!=expected_source.resolve() or Path(baseline.get('source','')).resolve()!=expected_old.resolve():
            raise ValueError('Quest input seed source snapshot path differs')
        materials={};aliases={}
        pointers=[rule['version_baseline'],target_pointer,check_pointer,*rule['consumers'].values()]
        for pointer in pointers:
            materials.update(core.lineage_inputs(args,Path(pointer['path'])))
            aliases[str(Path(pointer['path']).absolute())]=str(Path(pointer['path']).resolve())
        artifacts=declaration.get('artifacts')
        if not isinstance(artifacts,dict) or len(artifacts)>512:raise ValueError('Quest input seed target artifacts differ')
        for filename,expected in artifacts.items():
            path=Path(filename).resolve()
            if not path.is_relative_to(Path(args.root).resolve()) or not isinstance(expected,str) or not SHA.fullmatch(expected):
                raise ValueError('Quest input seed artifact outside library')
            if str(path) in materials and materials[str(path)]!=expected:raise ValueError('Quest input seed artifact lineage conflicts')
            if index.digest(path)!=expected:raise ValueError('Quest input seed declaration artifact changed')
            materials[str(path)]=expected
        selector=Path(args.knowledge)/'quest-input-seed.json'
        materials[str(selector.resolve())]=index.digest(selector)
        runtime=dict(portable=index.extension('stage-action-tools-v1').runtime(index),
            native=index.extension('update-native-harness').runtime_inputs(),
            files={str(p):index.digest(p) for p in index.extension('native-publication-v2').runtime_files()})
        args.source_store.source(roots['source_sha256']);args.source_store.source(sha)
        barrier_files={**materials,**tools,**runtime['files'],**runtime['portable'].get('files',{})}
        for filename,expected in barrier_files.items():
            if args.source_store.digest(filename)!=expected:
                raise ValueError('Quest input seed selected material changed')
        inputs=dict(recipe=RECIPE,baseline=dict(context=rule['version_baseline'],source_sha256=roots['source_sha256']),
            target=dict(context=target_pointer,source_sha256=sha,semantic_check=check_pointer),
            consumers=rule['consumers'],materials=materials,aliases=aliases,tools=tools,runtime=runtime,
            role_mapping=ROLE_MAP,root_inventory=roots)
        old=baseline['native_input']['functions'];new=target['native_input']['functions']
        mappings=[dict(role=input_role,baseline=old[input_role],target=new[input_role],
            consumers=[dict(consumer=name,role=consumer_role) for name in sorted(consumers)])
            for consumer_role,input_role in ROLE_MAP.items()]
        if (any(not isinstance(r['target'],str) or not ADDRESS.fullmatch(r['target']) for r in mappings)
                or len({r['target'] for r in mappings})!=7):
            raise ValueError('Quest input seed target primitives differ or alias')
        counts={key:roots[key] for key in ('unique_roots','shared_roots','mapped_roots','pending_roots')}
        expected_proof=dict(schema=2,recipe=RECIPE,method='static',inputs=inputs,mappings=mappings,inventory=roots,
            native_consumer_verified=False,runtime_activated=False,profile_activated=False,limits=LIMITS)

        def result_for(pointer):
            return dict(state='prepared_static',recipe=RECIPE,method='static',report=pointer['path'],sha256=pointer['sha256'],
                proof=pointer,mappings=mappings,inventory=roots,counts=counts,native_consumer_verified=False,
                runtime_activated=False,profile_activated=False,final_validation_completed=False,
                final_validation_pending=True,limits=LIMITS)

        def static_seed():
            native=index.extension('build-native-entry-code');bindings=index.extension('update-bindings')
            before=args.source_store.image(native,roots['source_sha256']);after=args.source_store.image(native,sha)
            if baseline.get('transfer_proof'):api.validate(index,args,baseline)
            api.validate(index,args,target)
            api.export_coverage(args.root,baseline,native,bindings,before)
            api.export_coverage(args.root,target,native,bindings,after)
            expected,relation=api.transfer(native,bindings,before,after,baseline,sha,expected_source)
            if api.plain(expected)!=api.plain(target):raise ValueError('Quest input seed differs from independent target VersionResult')
            mapping=relation.get('mapping',{})
            for input_role in ROLE_MAP.values():
                if mapping.get(old[input_role])!=new[input_role]:raise ValueError('Quest input seed relocated role differs: '+input_role)
            validate_relation(relation,mappings)
            proof=dict(expected_proof,transfer_relation=relation)
            raw=workflow.canonical(proof)
            if len(raw)>LIMIT:raise ValueError('Quest input seed proof exceeds budget')
            path=workflow.snapshot(args.root,CATEGORY,proof)
            return result_for(dict(path=str(path),sha256=index.digest(path)))

        result=journal.stage(STAGE,inputs,static_seed)
        pointer=result.get('proof') if isinstance(result,dict) else None
        if (not exact_pointer(pointer) or Path(pointer['path']).name!='manifest.json'
                or Path(pointer['path']).parent.name!=pointer['sha256']
                or result!=result_for(pointer)):
            raise ValueError('Quest input seed cached result scope or proof differs')
        proof=pointer_document(index,pointer,Path(args.root)/'knowledge'/CATEGORY)
        if set(proof)!=set(expected_proof)|{'transfer_relation'} or {k:v for k,v in proof.items() if k!='transfer_relation'}!=expected_proof:
            raise ValueError('Quest input seed cached proof fields differ')
        validate_relation(proof['transfer_relation'],mappings)
        # Journal reuse checks outputs; fresh selected materials and aliases are
        # still checked here while the ordinary updater retains its final barrier.
        if any(index.digest(p)!=expected for p,expected in barrier_files.items()) or any(
                str(Path(p).resolve())!=expected for p,expected in aliases.items()):
            raise ValueError('Quest input seed material changed during preparation')
        if configuration(index,args)!=rule or api.tools()!=declaration['dependencies']:
            raise ValueError('Quest input seed rules changed during preparation')
        if (index.extension('stage-action-tools-v1').runtime(index)!=runtime['portable']
                or index.extension('update-native-harness').runtime_inputs()!=runtime['native']
                or {str(p):index.digest(p) for p in index.extension('native-publication-v2').runtime_files()}!=runtime['files']):
            raise ValueError('Quest input seed runtime changed during preparation')
        scoped=getattr(args,'_scope_v2_state',None)
        owner=scoped.get('owner') if isinstance(scoped,dict) else None
        args._quest_input_seed_v2_state=dict(source_store=args.source_store,root=Path(args.root).resolve(),
            knowledge=Path(args.knowledge).resolve(),proof=copy.deepcopy(pointer),result=copy.deepcopy(result),
            rule=copy.deepcopy(rule),owner=owner)
        return result
    except (ValueError,OSError,KeyError,StopIteration) as error:
        return unavailable('quest_input_seed_rejected: '+str(error))


def finalize(index,args,result):
    """Fresh selected-file barrier immediately before ordinary bundle publication."""
    if not isinstance(result,dict) or result.get('state')!='prepared_static':return result
    state=getattr(args,'_quest_input_seed_v2_state',None)
    if (not isinstance(state,dict) or state.get('source_store') is not getattr(args,'source_store',None)
            or state.get('root')!=Path(args.root).resolve() or state.get('knowledge')!=Path(args.knowledge).resolve()
            or state.get('proof')!=result.get('proof') or state.get('result')!=result):
        raise ValueError('Quest input seed final owner/source/proof identity differs')
    scoped=getattr(args,'_scope_v2_state',None)
    owner=scoped.get('owner') if isinstance(scoped,dict) else None
    if (owner is not state.get('owner') or (owner is not None and (
            scoped.get('source_store') is not args.source_store or getattr(owner,'finished',False) is not True))):
        raise ValueError('Quest input seed final scoped owner differs or is not validated')
    pointer=state['proof']
    if (not exact_pointer(pointer) or Path(pointer['path']).name!='manifest.json'
            or Path(pointer['path']).parent.name!=pointer['sha256']):
        raise ValueError('Quest input seed final proof pointer differs')
    proof=pointer_document(index,pointer,Path(args.root)/'knowledge'/CATEGORY)
    inputs=proof.get('inputs')
    if (proof.get('schema')!=2 or proof.get('recipe')!=RECIPE or proof.get('method')!='static'
            or proof.get('mappings')!=result['mappings'] or proof.get('inventory')!=result['inventory']
            or proof.get('native_consumer_verified') is not False or proof.get('runtime_activated') is not False
            or proof.get('profile_activated') is not False or not isinstance(inputs,dict)):
        raise ValueError('Quest input seed final proof scope differs')
    validate_relation(proof.get('transfer_relation'),result['mappings'])
    runtime=inputs['runtime'];files={**inputs['materials'],**inputs['tools'],**runtime['files'],
        **runtime['portable'].get('files',{})}
    if any(index.digest(path)!=expected for path,expected in files.items()) or any(
            str(Path(path).resolve())!=expected for path,expected in inputs['aliases'].items()):
        raise ValueError('Quest input seed final selected file or alias changed')
    if configuration(index,args)!=state['rule']:
        raise ValueError('Quest input seed final selector changed')
    if (index.extension('stage-action-tools-v1').runtime(index)!=runtime['portable']
            or index.extension('update-native-harness').runtime_inputs()!=runtime['native']
            or {str(p):index.digest(p) for p in index.extension('native-publication-v2').runtime_files()}!=runtime['files']):
        raise ValueError('Quest input seed final runtime changed')
    # run() already registered both snapshots; the caller performs the ordinary
    # SourceStore.validate() before this check. Re-accessing cannot build a PE.
    for identity in (inputs['baseline']['source_sha256'],inputs['target']['source_sha256']):
        args.source_store.source(identity)
    return dict(result,final_validation_completed=True,final_validation_pending=False)
