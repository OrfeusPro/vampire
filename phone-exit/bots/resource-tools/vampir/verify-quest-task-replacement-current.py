"""Current kind-6 task creation/replacement with explicit engine boundaries."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
ROOT=Path('F:/PhoneExit Resources/Vampir')
CONTEXT=HERE/'knowledge/native-contexts/quest-task-replacement-current.json'
RECIPE='quest-task-replacement-current-v1'
SOURCE='03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
SHA=re.compile('[a-f0-9]{64}')
LIMITS=[
    'Native factory executes only kind 6 and its fallback after primary task allocation failure.',
    'Task/control constructors, shared move/release, state/progress and index getter execute with bounded memory and ABI checks.',
    'Allocation, nested initialization, task-data lookup, owner binding, lifecycle, destruction and free effects remain explicit fixtures.',
    'Synthetic task data and null parent weak control do not establish installed catalogue order, active task or real gameplay lifecycle.',
    'Qualified current projection/model and matching evidence is reused without replay; no runtime action admission, live mutation or network command is established.',
]


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def require(ok,why):
    if not ok:raise ValueError('Quest replacement: '+why)


def barrier(inputs):
    require(all(digest(name)==expected for name,expected in inputs.items()),'input SHA differs')


def definition(index,root,context_path):
    context_path=Path(context_path).resolve();raw=context_path.read_bytes();context=json.loads(raw)
    require(context.get('schema')==1 and context.get('recipe')==RECIPE
        and context.get('source_sha256')==SOURCE
        and set(context)=={'schema','recipe','source_sha256','exports','execution','model_proof'},'context scope differs')
    model=load('verify-quest-model-current')
    parent=model.document(context['model_proof'],root,'code-clues/'+model.RECIPE)
    _,parent_definition=model.definition(index,root,model.CONTEXT)
    model.validate(parent,parent_definition)
    barrier(parent_definition['inputs'])
    inputs=dict(parent_definition['inputs'])
    inputs[context['model_proof']['path']]=context['model_proof']['sha256']
    native=context['execution']['native']
    require(native['source_sha256']==SOURCE
        and Path(native['source']).resolve()==root/'client-code-snapshots'/SOURCE/'ProjectRED-Win64-Shipping.exe'
        and 1<=len(native['functions'])<=10 and len(native['fixtures'])<=32
        and len(native['leaves'])<=16,'execution source/budget differs')
    for path in (Path(__file__),HERE/'quest-task-replacement-current-cases-v1.py',
                 HERE/'verify-quest-model-current.py'):
        name=str(path.resolve());actual=digest(path)
        require(name not in inputs or inputs[name]==actual,'reused tool changed')
        inputs[name]=actual
    inputs[str(context_path)]=hashlib.sha256(raw).hexdigest()
    runtime={str(path):digest(path) for path in index.extension('native-publication-v2').runtime_files()}
    for name,expected in parent_definition['runtime_inputs'].items():
        require(name not in runtime or runtime[name]==expected,'reused runtime changed')
        runtime[name]=expected
    require(all(name not in inputs or inputs[name]==expected for name,expected in runtime.items()),'reused runtime changed')
    inputs.update(runtime)
    require(1<=len(context['exports'])<=4,'export budget differs')
    for run,expected in context['exports'].items():
        require(re.fullmatch('run-[0-9a-f]+',run) and SHA.fullmatch(expected),'export pointer differs')
        path=root/'ghidra/request-exports'/SOURCE/run/'details.json'
        require(str(path) not in inputs or inputs[str(path)]==expected,'reused export differs')
        inputs[str(path)]=expected
    return context,dict(source_sha256=SOURCE,inputs=inputs,runtime_inputs=runtime,model_proof=context['model_proof'])


def validate(report,selected):
    require(isinstance(selected,dict) and selected.get('source_sha256')==SOURCE
        and report.get('schema')==1 and report.get('recipe')==RECIPE
        and report.get('source_sha256')==SOURCE and report.get('definition')==selected
        and report.get('native_execution') is True and report.get('native_proofs_reused') is True
        and report.get('limits')==LIMITS
        and all(report.get(key) is False for key in ('runtime_admitted','network_used','active_task_verified',
            'ordered_catalog_verified','action_admitted','model_applied_online')),'receipt scope differs')
    load('quest-task-replacement-current-cases-v1').validate(report.get('result',{}))


def verify(*,root=ROOT,context_path=CONTEXT):
    index=load('knowledge-index').api();root=Path(root).resolve()
    context,selected=definition(index,root,context_path)
    workflow=index.extension('research-workflow');model=load('verify-quest-model-current')
    cache=root/'knowledge'/(RECIPE+'-cache')/(hashlib.sha256(workflow.canonical(selected)).hexdigest()+'.json')
    barrier(selected['inputs'])
    if cache.is_file():
        pointer=index.read_json(cache);report=model.document(pointer,root,'code-clues/'+RECIPE)
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
    result=load('quest-task-replacement-current-cases-v1').execute(index,root,context['execution'],exports,source)
    report=dict(schema=1,recipe=RECIPE,source_sha256=SOURCE,definition=selected,result=result,
        native_execution=True,native_proofs_reused=True,runtime_admitted=False,network_used=False,
        active_task_verified=False,ordered_catalog_verified=False,action_admitted=False,model_applied_online=False,limits=LIMITS)
    validate(report,selected);barrier(selected['inputs'])
    path=index.extension('audit-client-release').save_snapshot(root/'code-clues'/RECIPE,report)
    pointer=dict(path=str(path),sha256=digest(path));workflow.atomic(cache,workflow.canonical(pointer))
    return dict(report=str(path),sha256=pointer['sha256'],reused=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT)
    args=parser.parse_args();print(json.dumps(verify(root=args.root),ensure_ascii=False))
