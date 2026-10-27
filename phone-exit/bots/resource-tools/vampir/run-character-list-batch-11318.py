"""One cached offline CharacterList package; no login, network or profile activation."""
import argparse
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import sys

HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
NAMES=('waiting-end','character-list-envelope','character-record','character-extensions',
       'character-list-records','character-list-handler')
DEPENDENCIES=('run-character-list-batch-11318.py','update-native-harness.py',
    'build-native-entry-code.py','build-object-zero-init-code.py','extract-native-enums.py',
    'update-bindings.py','audit-launcher-shape-11318.py','knowledge-index.py',
    'research-workflow.py','version-gate-switch-11318.py',
    'login-result-string-fixtures.py','character-list-storage-fixtures.py',
    'requirements-native.txt')
EXPECTED={
    'waiting-end':{'cases':16,'fallback':8},
    'character-list-envelope':{'cases':24,'truncated':38,'failures':7},
    'character-record':{'cases':128,'truncated':201,'failures':128},
    'character-list-records':{'cases':32,'truncated':291,'failures':154},
    'character-list-handler':{'cases':101},
}


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def objects(value):
    if isinstance(value,dict):
        yield value
        for child in value.values():yield from objects(child)
    elif isinstance(value,list):
        for child in value:yield from objects(child)


def inputs(root):
    root=Path(root).resolve()
    source=root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'
    if digest(source)!=SHA:raise ValueError('CharacterList batch source SHA changed')
    contexts={};exports={};files=[HERE/name for name in DEPENDENCIES]
    for name in NAMES:
        path=HERE/'knowledge/native-contexts'/(name+'-11318.json')
        raw=path.read_bytes();context=json.loads(raw)
        if context.get('source_sha256')!=SHA or Path(context['source']).resolve()!=source:
            raise ValueError('CharacterList batch context source differs: '+name)
        contexts[name]=context;files.append(path)
        files.append(HERE/('verify-'+name+'-context.py'))
        stem=name.replace('-','_')
        files.extend(HERE.parents[1]/filename for filename in
                     ('test_vampir_'+stem+'_context.py','test_vampir_'+stem+'_11318.py'))
        declared={}
        for nested in objects(context):
            if 'source_sha256' in nested and nested['source_sha256']!=SHA:
                raise ValueError('CharacterList nested source differs')
            for run,expected in nested.get('exports',{}).items():
                if not re.fullmatch('run-[0-9a-f]{12}',run) or not re.fullmatch('[0-9a-f]{64}',expected):
                    raise ValueError('Invalid CharacterList export identity')
                if run in declared and declared[run]!=expected:raise ValueError('Conflicting CharacterList export hashes')
                declared[run]=expected
        if not declared:raise ValueError('CharacterList context has no exports')
        for run,expected in declared.items():
            path=root/'ghidra/request-exports'/SHA/run/'details.json'
            if str(path) in exports:
                if exports[str(path)]!=expected:raise ValueError('Conflicting CharacterList package exports')
                continue
            if digest(path)!=expected:raise ValueError('CharacterList batch export SHA changed')
            document=json.loads(path.read_bytes())
            if document.get('new_source_sha256')!=SHA:raise ValueError('CharacterList batch export source differs')
            exports[str(path)]=expected
    shared=HERE.parents[1]/'vampir-shared/vampir_core'
    files.extend(shared/name for name in ('character_list.py','login_result.py'))
    files.append(HERE.parents[1]/'test_vampir_update_contracts.py')
    definition=dict(source_sha256=SHA,source=str(source),python=platform.python_version(),
        executable=sys.executable,
        files={str(path.resolve()):digest(path) for path in sorted(set(files))},
        exports=exports,runtime=load('update-native-harness').runtime_inputs())
    return contexts,definition


def validate_report(name,report):
    if (report.get('source_sha256')!=SHA or report.get('network_used') is not False
            or report.get('profile_activated') is not False or not report.get('limits')):
        raise ValueError('CharacterList native report source/boundary differs: '+name)
    if name=='character-extensions':
        parts=report['components']
        counts={part['kind']:{key:len(part[key]) for key in ('cases','truncated','failures')} for part in parts}
        if counts!={'appearance':{'cases':5,'truncated':58,'failures':42},
                    'optional':{'cases':19,'truncated':201,'failures':94}}:
            raise ValueError('CharacterList extension coverage differs')
    elif {key:len(report[key]) for key in EXPECTED[name]}!=EXPECTED[name]:
        raise ValueError('CharacterList native coverage differs: '+name)


@contextmanager
def build_lock(root,key):
    """Never duplicate native work or remove another owner's stale lock automatically."""
    path=root/'knowledge/character-list-batch-cache-11318'/(key+'.lock')
    path.parent.mkdir(parents=True,exist_ok=True)
    owner=json.dumps(dict(pid=os.getpid(),key=key)).encode('utf-8')
    try:
        with path.open('xb') as stream:stream.write(owner)
    except FileExistsError:
        raise ValueError('CharacterList native package is already owned; inspect its lock/PID before retry') from None
    try:yield
    finally:
        if path.read_bytes()!=owner:raise ValueError('CharacterList native package lock owner changed')
        path.unlink()


def run(root,refresh=False):
    root=Path(root).resolve();contexts,definition=inputs(root)
    workflow=load('research-workflow')
    key=hashlib.sha256(workflow.canonical(definition)).hexdigest()
    cache=root/'knowledge/character-list-batch-cache-11318'/(key+'.json')
    if cache.is_file() and not refresh:
        pointer=json.loads(cache.read_bytes());path=Path(pointer['report']).resolve()
        if not path.is_relative_to(root/'knowledge/character-list-batch-verified-11318') or path.name!='manifest.json':
            raise ValueError('CharacterList cache report outside library')
        if digest(path)!=pointer['sha256'] or path.parent.name!=pointer['sha256']:
            raise ValueError('CharacterList cached report changed')
        result=json.loads(path.read_bytes())
        if (result['definition']!=definition or set(result['reports'])!=set(NAMES)
                or set(result['component_reports'])!=set(NAMES)
                or result.get('source_sha256')!=SHA or result.get('network_used') is not False
                or result.get('profile_activated') is not False or result.get('live_verified') is not False):
            raise ValueError('CharacterList cached definition/composition differs')
        for name,report in result['reports'].items():validate_report(name,report)
        for name,item in result['component_reports'].items():
            component=Path(item['path']).resolve()
            expected=root/'knowledge'/('native-'+name+'-checks')/item['sha256']/'manifest.json'
            if component!=expected or digest(component)!=item['sha256']:
                raise ValueError('CharacterList component report changed')
            if json.loads(component.read_bytes())!=result['reports'][name]:
                raise ValueError('CharacterList component report content differs')
        if inputs(root)[1]!=definition:raise ValueError('CharacterList inputs changed while reading cache')
        return path,result,True
    with build_lock(root,key):
        # Another consumer may have finished between our initial lookup and lock.
        if cache.is_file() and not refresh:return run(root)
        return build(root,contexts,definition,workflow,cache)


def build(root,contexts,definition,workflow,cache):
    reports={}
    for name in NAMES:
        report=load('verify-'+name+'-context').verify(contexts[name],root)
        validate_report(name,report)
        report.update(context_sha256=digest(HERE/'knowledge/native-contexts'/(name+'-11318.json')),
                      tool_sha256=digest(HERE/('verify-'+name+'-context.py')))
        reports[name]=report
    if inputs(root)[1]!=definition:raise ValueError('CharacterList inputs changed during native package')
    components={}
    for name,report in reports.items():
        path=workflow.snapshot(root,'native-'+name+'-checks',report)
        components[name]=dict(path=str(path),sha256=digest(path))
    result=dict(schema=1,source_sha256=SHA,definition=definition,reports=reports,
        component_reports=components,network_used=False,profile_activated=False,
        live_verified=False,
        limits=['Synthetic services, storage/rehash/copy/allocator and declared fixture boundaries remain explicit.',
                'Separate whole readers and handler checks do not prove shared reader-to-handler integration.',
                'No login, transport, server acceptance, character creation or runtime profile promotion.'])
    result=json.loads(json.dumps(result,ensure_ascii=False))
    path=workflow.snapshot(root,'character-list-batch-verified-11318',result)
    workflow.atomic(cache,workflow.canonical(dict(report=str(path),sha256=digest(path))))
    return path,result,False


def report_for(name,context,root):
    """Return only the current exact context's verified component, as an independent copy."""
    if name not in NAMES:raise ValueError('Unknown CharacterList package component')
    path=HERE/'knowledge/native-contexts'/(name+'-11318.json')
    if context!=json.loads(path.read_bytes()):raise ValueError('CharacterList requested context differs')
    _,result,_=run(root)
    if context!=json.loads(path.read_bytes()):raise ValueError('CharacterList requested context changed')
    return copy.deepcopy(result['reports'][name])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--refresh',action='store_true')
    args=parser.parse_args();path,result,reused=run(args.root,args.refresh)
    print(json.dumps(dict(report=str(path),components=len(result['reports']),reused=reused)))
