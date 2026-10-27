"""One source-bound cached Clock/Ping/world package; no login or network."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys

HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
ROOT=Path('F:/PhoneExit Resources/Vampir')
COMPONENTS={'clock':('replay-login-clock-11318','clock-replays-11318',24),
            'producer':('replay-login-ping-11318','clock-replays-11318',36),
            'world':('replay-world-entry-11318','ping-world-11318',201),
            'result':('replay-ping-result-11318','ping-world-11318',36)}
DEPENDENCIES=('run-clock-world-batch-11318.py','verify-clock-replay-source-11318.py',
    'verify-ping-world-source-11318.py','native-request-harness-11316.py',
    'build-native-entry-code.py','build-object-zero-init-code.py','extract-native-enums.py',
    'audit-launcher-shape-11318.py','knowledge-index.py','research-workflow.py',
    'audit-client-release.py','update-native-harness.py','requirements-native.txt',
    'knowledge/native-contexts/character-record-11318.json')


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def inputs(root):
    root=Path(root).resolve();source=root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'
    if digest(source)!=SHA:raise ValueError('Clock/world package source changed')
    paths={HERE/name for name in DEPENDENCIES};contexts={};exports={}
    for name,(tool,context_name,_) in COMPONENTS.items():
        path=HERE/'knowledge/native-contexts'/(context_name+'.json')
        context=json.loads(path.read_bytes())
        if context['source_sha256']!=SHA:raise ValueError('Clock/world context source differs')
        contexts[name]=context;paths.update((path,HERE/(tool+'.py')))
    for context in list(contexts.values())+[json.loads((HERE/'knowledge/native-contexts/character-record-11318.json').read_bytes())['native_input']]:
        if context['source_sha256']!=SHA:raise ValueError('Clock/world input source differs')
        for run,expected in context['exports'].items():
            if not run.startswith('run-') or '/' in run or '\\' in run:raise ValueError('Invalid package export')
            path=root/'ghidra/request-exports'/SHA/run/'details.json'
            if digest(path)!=expected or json.loads(path.read_bytes())['new_source_sha256']!=SHA:
                raise ValueError('Clock/world export source/hash changed')
            if str(path) in exports and exports[str(path)]!=expected:raise ValueError('Conflicting package export')
            exports[str(path)]=expected
    definition=dict(source_sha256=SHA,python=platform.python_version(),executable=sys.executable,
        files={str(p.resolve()):digest(p) for p in sorted(paths)},exports=exports,
        runtime=load('update-native-harness').runtime_inputs())
    return contexts,definition


@contextmanager
def locked(root,key):
    path=root/'knowledge/clock-world-batch-cache-11318'/(key+'.lock')
    path.parent.mkdir(parents=True,exist_ok=True);owner=json.dumps(dict(pid=os.getpid(),key=key)).encode()
    try:
        with path.open('xb') as stream:stream.write(owner)
    except FileExistsError:raise ValueError('Clock/world batch owned; inspect recorded PID before retry') from None
    try:yield
    finally:
        if path.read_bytes()!=owner:raise ValueError('Clock/world lock owner changed')
        path.unlink()


def validate(name,report):
    if (report['source_sha256']!=SHA or report.get('network_used') is not False
            or report.get('profile_activated') is not False or not report.get('limits')):
        raise ValueError('Clock/world report scope differs')
    if len(report['cases'])!=COMPONENTS[name][2]:raise ValueError('Clock/world coverage differs')
    if name=='clock' and len(report['lobby_cases'])!=10:raise ValueError('Lobby coverage differs')
    if name=='result' and len(report['short'])!=12:raise ValueError('Ping short-input coverage differs')


def run(root=ROOT,refresh=False):
    root=Path(root).resolve();contexts,definition=inputs(root);workflow=load('research-workflow')
    key=hashlib.sha256(workflow.canonical(definition)).hexdigest()
    cache=root/'knowledge/clock-world-batch-cache-11318'/(key+'.json')
    if cache.is_file() and not refresh:
        pointer=json.loads(cache.read_bytes());path=Path(pointer['report']).resolve()
        if (not path.is_relative_to(root/'knowledge/clock-world-batch-verified-11318')
                or path.name!='manifest.json' or path.parent.name!=pointer['sha256'] or digest(path)!=pointer['sha256']):
            raise ValueError('Clock/world cached report changed')
        result=json.loads(path.read_bytes())
        if (result['definition']!=definition or set(result['reports'])!=set(COMPONENTS)
                or set(result['components'])!=set(COMPONENTS) or result.get('network_used') is not False
                or result.get('profile_activated') is not False):raise ValueError('Clock/world cached composition differs')
        for name,report in result['reports'].items():
            validate(name,report);item=result['components'][name];component=Path(item['report']).resolve()
            if (not component.is_relative_to(root/'code-clues') or component.name!='manifest.json'
                    or component.parent.name!=item['sha256'] or digest(component)!=item['sha256']
                    or json.loads(component.read_bytes())!=report):raise ValueError('Clock/world component changed')
        if inputs(root)[1]!=definition:raise ValueError('Clock/world cache inputs changed')
        return path,result,True
    with locked(root,key):
        if cache.is_file() and not refresh:return run(root)
        reports={};components={}
        for name,(tool,_,_) in COMPONENTS.items():
            item=load(tool).verify(contexts[name]['exports']);path=Path(item['report']).resolve()
            if (not path.is_relative_to(root/'code-clues') or path.name!='manifest.json'
                    or path.parent.name!=item['sha256'] or digest(path)!=item['sha256']):
                raise ValueError('Clock/world replay report changed')
            report=json.loads(path.read_bytes());validate(name,report)
            reports[name]=report;components[name]=item
        if inputs(root)[1]!=definition:raise ValueError('Clock/world inputs changed during replay')
        result=dict(schema=1,source_sha256=SHA,definition=definition,reports=reports,components=components,
            network_used=False,profile_activated=False,live_verified=False,
            limits=['Explicit clock/engine/storage/send/recovery fixtures remain.',
                    'Bounded select/world IO slices do not prove all nested variants or live server acceptance.',
                    'No authentication, automatic reconnect, quests, creation or runtime promotion.'])
        path=workflow.snapshot(root,'clock-world-batch-verified-11318',result)
        workflow.atomic(cache,workflow.canonical(dict(report=str(path),sha256=digest(path))))
        return path,result,False


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT)
    parser.add_argument('--refresh',action='store_true');args=parser.parse_args()
    path,result,reused=run(args.root,args.refresh)
    print(json.dumps(dict(report=str(path),components=len(result['reports']),reused=reused)))
