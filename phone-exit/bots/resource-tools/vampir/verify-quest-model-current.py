"""Current task projection and model wrapper with immutable bounded evidence."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
ROOT=Path('F:/PhoneExit Resources/Vampir')
CONTEXT=HERE/'knowledge/native-contexts/quest-model-current.json'
RECIPE='quest-model-current-v1'
SOURCE='03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
SHA=re.compile('[a-f0-9]{64}')
LIMITS=[
    'Projection and hash-collision lookup execute on a synthetic manager and task array; population, CSV order and active task remain unverified.',
    'Model wrapper executes with native existing-task state/progress and copy; map, notification, setter and lifecycle effects are explicit fixtures.',
    'Factory switch, case-6 dependencies and copy anchors are static source evidence; factory/replacement execution remains open.',
    'The existing 324-case current matching-task proof is reused after exact matrix and retained-input checks, without replay.',
    'No corrected actor position, current action provider, action admission, live quest mutation or network command is established.',
]


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def require(ok,why):
    if not ok:raise ValueError('Quest model: '+why)


def barrier(inputs):
    require(all(digest(name)==expected for name,expected in inputs.items()),'input SHA differs')


def document(pointer,root,category,budget=8*1024*1024):
    path=Path(pointer['path']).resolve()
    require(SHA.fullmatch(pointer['sha256'])
        and path==root/category/pointer['sha256']/'manifest.json','receipt path differs')
    with path.open('rb') as stream:raw=stream.read(budget+1)
    require(len(raw)<=budget and hashlib.sha256(raw).hexdigest()==pointer['sha256'],'receipt SHA or size differs')
    return json.loads(raw)


def definition(index,root,context_path):
    context_path=Path(context_path).resolve();raw=context_path.read_bytes();context=json.loads(raw)
    require(context.get('schema')==1 and context.get('recipe')==RECIPE
        and context.get('source_sha256')==SOURCE and set(context)=={
            'schema','recipe','source_sha256','exports','projection','wrapper','factory_static','matching_proof'},
        'context scope differs')
    source=root/'client-code-snapshots'/SOURCE/'ProjectRED-Win64-Shipping.exe'
    for kind in ('projection','wrapper'):
        native=context[kind]['native']
        require(native['source_sha256']==SOURCE and Path(native['source']).resolve()==source
            and 1<=len(native['functions'])<=8 and len(native['fixtures'])<=24
            and len(native['leaves'])<=12,kind+' execution budget/source differs')
    matching=document(context['matching_proof'],root,'knowledge/quest-matching-state-checks-v1')
    require(matching.get('source_sha256')==SOURCE,'matching proof source differs')
    index.extension('quest-matching-state-native-v1').validate_report(index,matching,matching['inputs'])
    index.extension('quest-wire-harness-v1').verify_files(matching['inputs']['files'],matching['inputs']['aliases'])
    inputs=dict(matching['inputs']['files'])
    inputs[context['matching_proof']['path']]=context['matching_proof']['sha256']
    names=('quest-model-projection-cases-v1','quest-model-wrapper-cases-v1','quest-model-factory-static-v1',
        'quest-tutorial-state-harness-v1','build-native-entry-code','update-bindings','login-input-transfer-rules',
        'quest-action-transfer-rules-v1','version-system-transfer-rules','update-native-version-result',
        'update-native-contexts','native-publication-v2','research-workflow','audit-client-release','knowledge-index',
        'quest-matching-state-native-v1','quest-matching-state-cases-v1','quest-wire-harness-v1')
    for path in (Path(__file__),*(HERE/(name+'.py') for name in names)):
        name=str(path.resolve());actual=digest(path)
        require(name not in inputs or inputs[name]==actual,'reused input changed: '+name)
        inputs[name]=actual
    inputs[str(context_path)]=hashlib.sha256(raw).hexdigest();inputs[str(source)]=SOURCE
    runtime={str(path):digest(path) for path in index.extension('native-publication-v2').runtime_files()}
    # The retained proof also pins the Python helpers actually used by its validators.
    for name,expected in inputs.items():
        path=Path(name).resolve()
        if path.is_relative_to(Path(sys.base_prefix).resolve()):
            require(name not in runtime or runtime[name]==expected,'reused runtime changed')
            runtime[name]=expected
    require(all(name not in inputs or inputs[name]==expected for name,expected in runtime.items()),
        'reused runtime changed')
    inputs.update(runtime)
    require(1<=len(context['exports'])<=4,'export budget differs')
    for run,expected in context['exports'].items():
        require(re.fullmatch('run-[0-9a-f]+',run) and SHA.fullmatch(expected),'export pointer differs')
        path=root/'ghidra/request-exports'/SOURCE/run/'details.json'
        require(str(path) not in inputs or inputs[str(path)]==expected,'reused export differs')
        inputs[str(path)]=expected
    return context,dict(source_sha256=SOURCE,inputs=inputs,runtime_inputs=runtime,
        matching_proof=context['matching_proof'])


def validate(report,selected):
    require(isinstance(selected,dict) and selected.get('source_sha256')==SOURCE
        and report.get('schema')==1 and report.get('recipe')==RECIPE
        and report.get('source_sha256')==SOURCE and report.get('definition')==selected
        and report.get('native_execution') is True and report.get('native_proofs_reused') is True
        and report.get('matching_cases_reused')==324 and report.get('limits')==LIMITS
        and all(report.get(key) is False for key in ('runtime_admitted','network_used','active_task_verified',
            'ordered_catalog_verified','action_admitted','factory_executed','model_applied_online'))
        and set(report.get('results',{}))=={'projection','wrapper','factory_static'},'receipt scope differs')
    for kind in ('projection','wrapper'):
        load('quest-model-'+kind+'-cases-v1').validate(report['results'][kind])
    load('quest-model-factory-static-v1').validate(report['results']['factory_static'])


def verify(*,root=ROOT,context_path=CONTEXT):
    index=load('knowledge-index').api();root=Path(root).resolve()
    context,selected=definition(index,root,context_path)
    workflow=index.extension('research-workflow')
    cache=root/'knowledge'/(RECIPE+'-cache')/(hashlib.sha256(workflow.canonical(selected)).hexdigest()+'.json')
    barrier(selected['inputs'])
    if cache.is_file():
        pointer=index.read_json(cache);report=document(pointer,root,'code-clues/'+RECIPE)
        validate(report,selected);barrier(selected['inputs'])
        return dict(report=pointer['path'],sha256=pointer['sha256'],reused=True)
    exports=[]
    for run,expected in context['exports'].items():
        path=root/'ghidra/request-exports'/SOURCE/run/'details.json'
        with path.open('rb') as stream:raw=stream.read(32*1024*1024+1)
        require(len(raw)<=32*1024*1024 and hashlib.sha256(raw).hexdigest()==expected,'export changed/oversized')
        exports.append(json.loads(raw))
    source=(root/'client-code-snapshots'/SOURCE/'ProjectRED-Win64-Shipping.exe').read_bytes()
    require(hashlib.sha256(source).hexdigest()==SOURCE,'source changed')
    results={kind:load('quest-model-'+kind+'-cases-v1').execute(index,root,context[kind],exports,source)
        for kind in ('projection','wrapper')}
    results['factory_static']=load('quest-model-factory-static-v1').verify(
        index,root,context['factory_static'],exports,source)
    report=dict(schema=1,recipe=RECIPE,source_sha256=SOURCE,definition=selected,
        native_execution=True,native_proofs_reused=True,matching_cases_reused=324,results=results,
        runtime_admitted=False,network_used=False,active_task_verified=False,ordered_catalog_verified=False,
        action_admitted=False,factory_executed=False,model_applied_online=False,limits=LIMITS)
    validate(report,selected);barrier(selected['inputs'])
    path=index.extension('audit-client-release').save_snapshot(root/'code-clues'/RECIPE,report)
    pointer=dict(path=str(path),sha256=digest(path));workflow.atomic(cache,workflow.canonical(pointer))
    return dict(report=str(path),sha256=pointer['sha256'],reused=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT)
    args=parser.parse_args();print(json.dumps(verify(root=args.root),ensure_ascii=False))
