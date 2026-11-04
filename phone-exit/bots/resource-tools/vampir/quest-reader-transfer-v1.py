"""Static consumer contexts from the ordered INPUT seed; no packet admission."""
import copy
import hashlib
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
RECIPE='quest-reader-transfer-v1'
STAGE='quest-reader-transfer-v1'
CATEGORY='quest-reader-transfer-proofs-v1'
LIMIT=32*1024*1024
SHA=re.compile('[0-9a-f]{64}')
LIMITS=[
    'Whole consumer root instruction/control and declared leaf/table/fixture links are checked statically.',
    'No target packet native scenario, handler application, storage effect or game command has been executed.',
    'Static contexts do not grant consumer semantic, runtime, profile or online admission.']


def configuration(args):
    path=Path(args.knowledge)/'quest-reader-transfer.json'
    if not path.is_file():return None
    with path.open('rb') as stream:raw=stream.read(8193)
    value=json.loads(raw)
    if (len(raw)>8192 or value!={'schema':1,'recipe':RECIPE}
            or not isinstance(value,dict) or type(value.get('schema')) is not int):
        raise ValueError('Unknown quest reader transfer rule')
    return value


def runtime(index):
    return dict(portable=index.extension('stage-action-tools-v1').runtime(index),
        native=index.extension('update-native-harness').runtime_inputs(),
        files={str(p):index.digest(p) for p in index.extension('native-publication-v2').runtime_files()})


def unavailable(reason):
    return dict(state='requires_review',recipe=RECIPE,method='static',reason=reason,
        native_consumer_verified=False,runtime_activated=False,profile_activated=False,limits=LIMITS)


def verify_files(index,files,aliases):
    if any(index.digest(path)!=expected for path,expected in files.items()) or any(
            str(Path(path).resolve())!=expected for path,expected in aliases.items()):
        raise ValueError('Quest reader transfer selected input or alias changed')


def validate_result(index,args,result,inputs,rules):
    seed=index.extension('quest-input-seed-v2')
    pointer=result.get('proof') if isinstance(result,dict) else None
    if (not seed.exact_pointer(pointer) or Path(pointer['path']).name!='manifest.json'
            or Path(pointer['path']).parent.name!=pointer['sha256']):
        raise ValueError('Quest reader transfer proof pointer differs')
    proof=seed.pointer_document(index,pointer,Path(args.root)/'knowledge'/CATEGORY)
    expected=dict(schema=1,recipe=RECIPE,method='static',inputs=inputs,
        native_consumer_verified=False,runtime_activated=False,profile_activated=False,limits=LIMITS)
    if set(proof)!=set(expected)|{'package'} or any(proof.get(k)!=v for k,v in expected.items()):
        raise ValueError('Quest reader transfer cached proof scope differs')
    rules.validate_package(proof['package'],inputs)
    wanted=dict(state='prepared_static',recipe=RECIPE,method='static',report=pointer['path'],
        sha256=pointer['sha256'],proof=pointer,counts=copy.deepcopy(proof['package']['counts']),
        native_consumer_verified=False,runtime_activated=False,profile_activated=False,
        final_validation_completed=False,final_validation_pending=True,limits=LIMITS)
    if result!=wanted:raise ValueError('Quest reader transfer cached result differs')
    return proof


def run(index,args,sha,journal,seed_result):
    rule=configuration(args)
    if rule is None:return dict(state='disabled',recipe=RECIPE)
    seed=index.extension('quest-input-seed-v2')
    if (not isinstance(sha,str) or not SHA.fullmatch(sha)
            or not isinstance(seed_result,dict) or seed_result.get('state')!='prepared_static'):
        return unavailable('quest_input_seed_not_prepared')
    state=getattr(args,'_quest_input_seed_v2_state',None)
    if (not isinstance(state,dict) or state.get('source_store') is not getattr(args,'source_store',None)
            or state.get('result')!=seed_result or state.get('proof')!=seed_result.get('proof')
            or state.get('root')!=Path(args.root).resolve() or state.get('knowledge')!=Path(args.knowledge).resolve()):
        return unavailable('quest_input_seed_invocation_identity_differs')
    scoped=getattr(args,'_scope_v2_state',None)
    owner=scoped.get('owner') if isinstance(scoped,dict) else None
    if owner is not state.get('owner') or (owner is not None and (
            scoped.get('source_store') is not args.source_store or getattr(owner,'closed',True) is not False)):
        return unavailable('quest_input_seed_scoped_owner_differs_or_closed')
    rules=index.extension('quest-reader-transfer-rules-v1');workflow=index.extension('research-workflow')
    original=args.source_store.index
    try:
        seed_proof=seed.pointer_document(index,seed_result['proof'],Path(args.root)/'knowledge'/seed.CATEGORY)
        if (seed_proof.get('recipe')!=seed.RECIPE or seed_proof.get('method')!='static'
                or seed_proof.get('native_consumer_verified') is not False
                or seed_proof.get('runtime_activated') is not False or seed_proof.get('profile_activated') is not False
                or seed_proof['inputs']['target']['source_sha256']!=sha):
            raise ValueError('Quest reader transfer seed scope or source differs')
        seed.validate_relation(seed_proof['transfer_relation'],seed_proof['mappings'])
        tools={**rules.tools(),str(Path(__file__).resolve()):index.digest(Path(__file__)),
            str(HERE/'quest-input-seed-v2.py'):index.digest(HERE/'quest-input-seed-v2.py')}
        selector=Path(args.knowledge)/'quest-reader-transfer.json'
        files={**seed_proof['inputs']['materials'],**seed_proof['inputs']['tools'],
            seed_result['proof']['path']:seed_result['proof']['sha256'],
            str(selector.resolve()):index.digest(selector),**tools}
        aliases={**seed_proof['inputs']['aliases'],str(selector.absolute()):str(selector.resolve())}
        current_runtime=runtime(index)
        files.update(current_runtime['files']);files.update(current_runtime['portable'].get('files',{}))
        verify_files(original,files,aliases)
        for path,expected in files.items():
            if args.source_store.digest(path)!=expected:raise ValueError('Quest reader transfer retained input differs')
        for source in (seed_proof['inputs']['baseline']['source_sha256'],sha):args.source_store.source(source)
        inputs=dict(recipe=RECIPE,seed=copy.deepcopy(seed_result['proof']),
            baseline_source_sha256=seed_proof['inputs']['baseline']['source_sha256'],target_source_sha256=sha,
            consumers=copy.deepcopy(seed_proof['inputs']['consumers']),files=files,aliases=aliases,
            tools=tools,runtime=current_runtime)

        def transfer():
            package=rules.transfer(index,args,seed_proof)
            rules.validate_package(package,inputs)
            proof=dict(schema=1,recipe=RECIPE,method='static',inputs=inputs,package=package,
                native_consumer_verified=False,runtime_activated=False,profile_activated=False,limits=LIMITS)
            raw=workflow.canonical(proof)
            if len(raw)>LIMIT:raise ValueError('Quest reader transfer proof budget exceeded')
            path=workflow.snapshot(args.root,CATEGORY,proof)
            pointer=dict(path=str(path),sha256=index.digest(path))
            return dict(state='prepared_static',recipe=RECIPE,method='static',report=str(path),sha256=pointer['sha256'],
                proof=pointer,counts=copy.deepcopy(package['counts']),native_consumer_verified=False,
                runtime_activated=False,profile_activated=False,final_validation_completed=False,
                final_validation_pending=True,limits=LIMITS)

        result=journal.stage(STAGE,inputs,transfer)
        validate_result(original,args,result,inputs,rules)
        verify_files(original,files,aliases)
        if configuration(args)!=rule or runtime(original)!=current_runtime:
            raise ValueError('Quest reader transfer selector or runtime changed')
        scoped=getattr(args,'_scope_v2_state',None)
        args._quest_reader_transfer_v1_state=dict(source_store=args.source_store,root=Path(args.root).resolve(),
            knowledge=Path(args.knowledge).resolve(),inputs=copy.deepcopy(inputs),rule=rule,result=copy.deepcopy(result),
            owner=scoped.get('owner') if isinstance(scoped,dict) else None)
        return result
    except (ValueError,OSError,KeyError,StopIteration) as error:
        return unavailable('quest_reader_transfer_rejected: '+str(error))


def finalize(index,args,result):
    if not isinstance(result,dict) or result.get('state')!='prepared_static':return result
    state=getattr(args,'_quest_reader_transfer_v1_state',None)
    if (not isinstance(state,dict) or state.get('source_store') is not getattr(args,'source_store',None)
            or state.get('result')!=result or state.get('root')!=Path(args.root).resolve()
            or state.get('knowledge')!=Path(args.knowledge).resolve()):
        raise ValueError('Quest reader transfer final invocation differs')
    scoped=getattr(args,'_scope_v2_state',None)
    owner=scoped.get('owner') if isinstance(scoped,dict) else None
    if owner is not state.get('owner') or (owner is not None and (
            scoped.get('source_store') is not args.source_store or getattr(owner,'finished',False) is not True)):
        raise ValueError('Quest reader transfer final scoped owner differs or is not validated')
    inputs=state['inputs'];rules=index.extension('quest-reader-transfer-rules-v1')
    validate_result(index,args,result,inputs,rules)
    verify_files(index,inputs['files'],inputs['aliases'])
    if configuration(args)!=state['rule'] or runtime(index)!=inputs['runtime']:
        raise ValueError('Quest reader transfer final rule or runtime changed')
    for source in (inputs['baseline_source_sha256'],inputs['target_source_sha256']):args.source_store.source(source)
    return dict(result,final_validation_completed=True,final_validation_pending=False)
