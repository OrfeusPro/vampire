"""One cached offline SDK/GMC2/NID package; never logs in or activates profiles."""
import argparse
import hashlib
import importlib.util
import json
import locale
from pathlib import Path
import platform
import sys

HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
CASES={
    'replay-sdk-defaults-11318':9,
    'replay-sdk-overrides-11318':106,
    'replay-sdk-platform-11318':12,
    'replay-gmc2-base-11318':512,
    'replay-gmc2-url-11318':27,
    'replay-gmc2-headers-11318':73,
    'replay-gmc2-geo-11318':672,
    'replay-nid-context-11318':32,
    'replay-nid-result-11318':1100,
    'replay-nid-primitives-11318':1124,
}
DEPENDENCIES=('run-sdk-batch-11318.py','verify-sdk-batch-11318.py',
    'native-request-harness-11316.py','update-native-harness.py','build-native-entry-code.py',
    'build-object-zero-init-code.py','extract-native-enums.py','research-workflow.py',
    'audit-launcher-shape-11318.py','knowledge-index.py','build-sdk-profile-11316.py')


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(root,refresh=False):
    root=Path(root);context_path=HERE/'knowledge/native-contexts/sdk-batch-11318.json'
    context=json.loads(context_path.read_text('utf-8'))
    guard=load('verify-sdk-batch-11318').verify(context,root)
    files=[context_path]+[HERE/name for name in DEPENDENCIES]+[HERE/name for name in context['generated_files']]
    shared=HERE.parents[1]/'vampir-shared/vampir_core'
    files += [shared/name for name in ('sdk_config.py','gmc2_request.py')]
    workflow=load('research-workflow');crt,=workflow.system_runtime_files(['ucrtbase.dll'])
    definition=dict(source_sha256=SHA,python=platform.python_version(),executable=sys.executable,
        files={str(path.resolve()):digest(path) for path in sorted(set(files))},
        exports={item['path']:item['sha256'] for item in guard['evidence']},
        runtime=load('update-native-harness').runtime_inputs(),
        crt=dict(path=str(crt),sha256=digest(crt),python_locale=locale.setlocale(locale.LC_ALL)))
    key=hashlib.sha256(workflow.canonical(definition)).hexdigest()
    cache=root/'knowledge/sdk-batch-cache-11318'/(key+'.json')
    if cache.is_file() and not refresh:
        pointer=json.loads(cache.read_text('utf-8'));path=Path(pointer['report'])
        if not path.resolve().is_relative_to((root/'knowledge/sdk-batch-verified-11318').resolve()):
            raise ValueError('SDK batch cache report outside library')
        if digest(path)!=pointer['sha256'] or path.parent.name!=pointer['sha256']:
            raise ValueError('SDK batch cache report changed')
        report=json.loads(path.read_text('utf-8'))
        if report['definition']!=definition:raise ValueError('SDK batch cache definition differs')
        return path,report,True
    reports={}
    for name,count in CASES.items():
        report=load(name).replay(root=root)
        if report['source_sha256']!=SHA or len(report['cases'])!=count or report.get('network_ready',False):
            raise ValueError('SDK native report coverage/source differs: '+name)
        reports[name]=report
    audit=load('audit-nid-result-11318').audit(root=root)
    if audit['source_sha256']!=SHA or len(audit['bindings'])!=7 or audit['network_ready']:
        raise ValueError('SDK NID result audit differs')
    helpers=reports['replay-nid-primitives-11318']
    if not helpers['native_primitives'] or {key:len(rows) for key,rows in helpers['primitive_cases'].items()}!={'numeric':112,'channels':176}:
        raise ValueError('SDK actual primitive coverage differs')
    # The original assembler is reused for the shared cross-component rules.
    # It consumes actual native outputs; no missing value comes from a default.
    aliases=dict(defaults='replay-sdk-defaults-11318',override='replay-sdk-overrides-11318',
        platform='replay-sdk-platform-11318',start='replay-gmc2-base-11318',
        url='replay-gmc2-url-11318',headers='replay-gmc2-headers-11318')
    profile=load('build-sdk-profile-11316').assemble({key:reports[name] for key,name in aliases.items()})
    if any(digest(path)!=sha for path,sha in definition['files'].items()) or digest(crt)!=definition['crt']['sha256']:
        raise ValueError('SDK batch inputs changed during replay')
    if locale.setlocale(locale.LC_ALL)!=definition['crt']['python_locale']:
        raise ValueError('SDK batch CRT locale changed')
    result=dict(schema=1,definition=definition,source_sha256=SHA,guard=guard,reports=reports,
        nid_audit=audit,profile_candidate=profile,native_case_executions=sum(CASES.values()),
        primitive_cases={'numeric':112,'channels':176},network_used=False,profile_activated=False,
        active_runtime_settings_verified=False,
        limits=['Declared synthetic storage/JSON/SDK/backend/HTTP boundaries remain fixtures.',
                'NID query/extensions/browser and real dispatcher/auth/session not proved by this batch.',
                'The assembled candidate does not activate runtime or establish server acceptance.'])
    result=json.loads(json.dumps(result,ensure_ascii=False))
    path=workflow.snapshot(root,'sdk-batch-verified-11318',result)
    workflow.atomic(cache,workflow.canonical(dict(report=str(path),sha256=digest(path))))
    return path,result,False


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--refresh',action='store_true')
    args=parser.parse_args();path,report,reused=run(args.root,args.refresh)
    print(json.dumps(dict(report=str(path),native_cases=report['native_case_executions'],reused=reused)))
