"""One cached source-bound Version/Login preparation and VersionResult replay; no runtime admission."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import sys

HERE = Path(__file__).resolve().parent
SHA = '544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c'
ROOT = Path('F:/PhoneExit Resources/Vampir')
COMPONENTS = {
 'version-prepare':('verify-version-prepare-context',64),
 'version-nm-device':('verify-version-nm-device-context',36),
 'version-cpu':('verify-version-cpu-context',72),
 'version-windows':('verify-version-windows-context',48),
 'version-combiner':('verify-version-combiner-context',256),
 'version-platform':('verify-version-platform-context',116),
 'version-prepare-nm':('verify-version-prepare-context',64),
 'version-prepare-system':('verify-version-prepare-context',64),
 'version-prepare-combiner':('verify-version-prepare-context',64),
 'version-prepare-platform':('verify-version-prepare-context',288),
 'version-result':('verify-version-result-context',32),
 'login-prepare':('verify-login-prepare-context',672),
 'login-prepare-sdk':('verify-login-prepare-context',2016),
 'login-metadata':('verify-login-metadata-context',288),
 'login-prepare-metadata':('verify-login-prepare-context',448),
}
DEPENDENCIES = ('run-entry-batch-11320.py','update-native-harness.py',
 'update-bindings.py','build-native-entry-code.py','extract-native-enums.py',
 'build-object-zero-init-code.py','audit-launcher-shape-11318.py',
 'research-workflow.py','knowledge-index.py','requirements-native.txt',
 'login-sdk-fixtures.py','login-result-input-fixtures.py','version-system-fixtures.py',
 'version-combiner-fixtures.py','version-platform-fixtures.py',
 '../../vampir-shared/vampir_core/version_result.py')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inputs(root):
    root = Path(root).resolve()
    source = root / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe'
    if digest(source) != SHA:
        raise ValueError('Entry batch source changed')
    contexts, files, exports = {}, {}, {}
    for name in set(DEPENDENCIES) | {tool+'.py' for tool,_ in COMPONENTS.values()}:
        path = (HERE / name).resolve()
        files[str(path)] = digest(path)
    for name in COMPONENTS:
        path = HERE / 'knowledge/native-contexts' / (name + '-11320.json')
        raw = path.read_bytes()
        context = json.loads(raw)
        if (context.get('schema') != 1 or context.get('source_sha256') != SHA
                or Path(context.get('source', '')).resolve() != source
                or context.get('verify_whole_exports') is not True):
            raise ValueError('Entry batch context source or whole-export scope differs')
        if type(context.get('exports')) is not dict or not 1 <= len(context['exports']) <= 8:
            raise ValueError('Entry batch export budget differs')
        contexts[name] = context
        files[str(path.resolve())] = hashlib.sha256(raw).hexdigest()
        for run, expected in context['exports'].items():
            if (type(run) is not str or not re.fullmatch(r'run-[a-zA-Z0-9_-]{1,128}', run)
                    or type(expected) is not str or not re.fullmatch(r'[0-9a-f]{64}', expected)):
                raise ValueError('Invalid explicit entry batch export')
            export = root / 'ghidra/request-exports' / SHA / run / 'details.json'
            payload = export.read_bytes()
            if (hashlib.sha256(payload).hexdigest() != expected
                    or json.loads(payload).get('new_source_sha256') != SHA):
                raise ValueError('Entry batch export source or hash differs')
            if str(export) in exports and exports[str(export)] != expected:
                raise ValueError('Conflicting entry batch export identity')
            exports[str(export)] = expected
    definition = dict(schema=1, source_sha256=SHA, python=platform.python_version(),
        executable=sys.executable, files=files, exports=exports,
        runtime=load('update-native-harness').runtime_inputs())
    return contexts, definition


@contextmanager
def locked(root, key):
    path = root / 'knowledge/entry-batch-cache-11320' / (key + '.lock')
    path.parent.mkdir(parents=True, exist_ok=True)
    owner = json.dumps(dict(pid=os.getpid(), key=key)).encode()
    try:
        with path.open('xb') as stream:
            stream.write(owner)
    except FileExistsError:
        raise ValueError('Entry batch owned; inspect recorded PID before retry') from None
    try:
        yield
    finally:
        if path.read_bytes() != owner:
            raise ValueError('Entry batch lock owner changed')
        path.unlink()


def validate(name, report, context, root, definition):
    if (report.get('source_sha256')!=SHA or report.get('method')!='bounded_native'
            or report.get('network_used') is not False or report.get('profile_activated') is not False
            or not report.get('limits') or len(report.get('cases',[]))!=COMPONENTS[name][1]):
        raise ValueError('Entry component source/scope/coverage differs: '+name)
    if any(row.get('guards') is False for row in report['cases']):raise ValueError('Entry guards differ')
    evidence=report.get('evidence')
    if not isinstance(evidence,list) or not evidence:raise ValueError('Entry evidence absent')
    for row in evidence:
        if definition['exports'].get(row['path'])!=row['sha256']:raise ValueError('Entry export provenance differs')
    if name=='version-result':
        if (len(report['truncated']),len(report['failures']),len(report['construction_cases']))!=(17,5,72):raise ValueError('VersionResult coverage differs')


def validate_batch(result, contexts, definition, root):
    if (result.get('schema') != 1 or result.get('source_sha256') != SHA
            or result.get('definition') != definition or set(result.get('reports', {})) != set(COMPONENTS)
            or result.get('native_case_executions') != 4622
            or result.get('network_used') is not False or result.get('profile_activated') is not False
            or result.get('runtime_activated') is not False or result.get('live_verified') is not False):
        raise ValueError('Entry batch composition differs')
    for name, report in result['reports'].items():
        validate(name, report, contexts[name], root, definition)


def run(root=ROOT, refresh=False):
    if type(refresh) is not bool:
        raise ValueError('Explicit entry batch refresh required')
    root = Path(root).resolve()
    contexts, definition = inputs(root)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(definition)).hexdigest()
    cache = root / 'knowledge/entry-batch-cache-11320' / (key + '.json')
    if cache.is_file() and not refresh:
        pointer = json.loads(cache.read_bytes())
        path = Path(pointer['report']).resolve()
        if (not path.is_relative_to(root / 'knowledge/entry-batch-verified-11320')
                or path.name != 'manifest.json' or path.parent.name != pointer['sha256']
                or digest(path) != pointer['sha256']):
            raise ValueError('Entry batch cached report changed')
        result = json.loads(path.read_bytes())
        validate_batch(result, contexts, definition, root)
        if inputs(root)[1] != definition:
            raise ValueError('Entry batch cache inputs changed')
        return path, result, True
    with locked(root, key):
        if cache.is_file() and not refresh:
            return run(root)
        reports = {}
        for name, (tool, _) in COMPONENTS.items():
            report = load(tool).verify(contexts[name], root)
            validate(name, report, contexts[name], root, definition)
            reports[name] = report
        if inputs(root)[1] != definition:
            raise ValueError('Entry batch inputs changed during replay')
        result = dict(schema=1, source_sha256=SHA, definition=definition, reports=reports,
            native_case_executions=4622, network_used=False, profile_activated=False,
            runtime_activated=False, live_verified=False,
            limits=['Whole Version/Login preparation and VersionResult within explicit bounded fixtures.',
                'SDK/OS/storage/allocator/string/send effects remain declared fixtures.',
                'LoginResult changed layout, post-state boundary and runtime admission remain unresolved.'])
        validate_batch(result, contexts, definition, root)
        path = workflow.snapshot(root, 'entry-batch-verified-11320', result)
        workflow.atomic(cache, workflow.canonical(dict(report=str(path), sha256=digest(path))))
        return path, result, False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--refresh', action='store_true')
    args = parser.parse_args()
    path, report, reused = run(args.root, args.refresh)
    print(json.dumps(dict(report=str(path), sha256=digest(path),
        native_cases=report['native_case_executions'], reused=reused)))
