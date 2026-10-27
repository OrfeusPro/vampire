"""One cached source-bound UTF-8/string/archive replay; no runtime admission."""
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
COMPONENTS = {'utf8': ('verify-utf8-context', 142, 'scalar_cases', 80),
              'string-writer': ('verify-string-writer-context', 228, None, 0),
              'archive-wire': ('verify-archive-wire-context', 45, 'wire_cases', 64)}
DEPENDENCIES = ('run-wire-batch-11320.py', 'verify-utf8-context.py',
    'verify-string-writer-context.py', 'verify-archive-wire-context.py',
    'update-native-harness.py', 'update-bindings.py', 'build-native-entry-code.py',
    'build-object-zero-init-code.py', 'extract-native-enums.py',
    'audit-launcher-shape-11318.py', 'knowledge-index.py',
    'research-workflow.py', 'requirements-native.txt')


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
        raise ValueError('Wire batch source changed')
    contexts, files, exports = {}, {}, {}
    for name in DEPENDENCIES:
        path = (HERE / name).resolve()
        files[str(path)] = digest(path)
    for name in COMPONENTS:
        path = HERE / 'knowledge/native-contexts' / (name + '-11320.json')
        raw = path.read_bytes()
        context = json.loads(raw)
        if (context.get('schema') != 1 or context.get('source_sha256') != SHA
                or Path(context.get('source', '')).resolve() != source
                or context.get('verify_whole_exports') is not True):
            raise ValueError('Wire batch context source or whole-export scope differs')
        if type(context.get('exports')) is not dict or not 1 <= len(context['exports']) <= 8:
            raise ValueError('Wire batch export budget differs')
        contexts[name] = context
        files[str(path.resolve())] = hashlib.sha256(raw).hexdigest()
        for run, expected in context['exports'].items():
            if (type(run) is not str or not re.fullmatch(r'run-[a-zA-Z0-9_-]{1,128}', run)
                    or type(expected) is not str or not re.fullmatch(r'[0-9a-f]{64}', expected)):
                raise ValueError('Invalid explicit wire batch export')
            export = root / 'ghidra/request-exports' / SHA / run / 'details.json'
            payload = export.read_bytes()
            if (hashlib.sha256(payload).hexdigest() != expected
                    or json.loads(payload).get('new_source_sha256') != SHA):
                raise ValueError('Wire batch export source or hash differs')
            if str(export) in exports and exports[str(export)] != expected:
                raise ValueError('Conflicting wire batch export identity')
            exports[str(export)] = expected
    definition = dict(schema=1, source_sha256=SHA, python=platform.python_version(),
        executable=sys.executable, files=files, exports=exports,
        runtime=load('update-native-harness').runtime_inputs())
    return contexts, definition


@contextmanager
def locked(root, key):
    path = root / 'knowledge/wire-batch-cache-11320' / (key + '.lock')
    path.parent.mkdir(parents=True, exist_ok=True)
    owner = json.dumps(dict(pid=os.getpid(), key=key)).encode()
    try:
        with path.open('xb') as stream:
            stream.write(owner)
    except FileExistsError:
        raise ValueError('Wire batch owned; inspect recorded PID before retry') from None
    try:
        yield
    finally:
        if path.read_bytes() != owner:
            raise ValueError('Wire batch lock owner changed')
        path.unlink()


def validate(name, report, context, root, definition):
    _, expected_cases, extra_key, expected_extra = COMPONENTS[name]
    if (report.get('source_sha256') != SHA or report.get('method') != 'bounded_native'
            or report.get('network_used') is not False or report.get('profile_activated') is not False
            or not report.get('limits') or type(report.get('cases')) is not list
            or len(report['cases']) != expected_cases):
        raise ValueError('Wire batch component source, scope or coverage differs')
    if extra_key and (type(report.get(extra_key)) is not list or len(report[extra_key]) != expected_extra):
        raise ValueError('Wire batch component additional coverage differs')
    if name == 'utf8' and any(row.get('guards') is not True for row in report['cases'] + report['scalar_cases']):
        raise ValueError('Wire batch UTF-8 guards differ')
    if name == 'string-writer' and any(row.get('guards') is not True for row in report['cases']):
        raise ValueError('Wire batch string guards differ')
    if name == 'archive-wire' and any(row.get('guards') is not True for row in report['wire_cases']):
        raise ValueError('Wire batch packet guards differ')
    expected = {str(root / 'ghidra/request-exports' / SHA / run / 'details.json'): value
        for run, value in context['exports'].items()}
    evidence = report.get('evidence')
    if (type(evidence) is not list or len(evidence) != len(expected)
            or {row['path']: row['sha256'] for row in evidence} != expected
            or any(definition['exports'].get(path) != value for path, value in expected.items())):
        raise ValueError('Wire batch component export provenance differs')


def validate_batch(result, contexts, definition, root):
    if (result.get('schema') != 1 or result.get('source_sha256') != SHA
            or result.get('definition') != definition or set(result.get('reports', {})) != set(COMPONENTS)
            or result.get('native_case_executions') != 559
            or result.get('network_used') is not False or result.get('profile_activated') is not False
            or result.get('runtime_activated') is not False or result.get('live_verified') is not False):
        raise ValueError('Wire batch composition differs')
    for name, report in result['reports'].items():
        validate(name, report, contexts[name], root, definition)


def run(root=ROOT, refresh=False):
    if type(refresh) is not bool:
        raise ValueError('Explicit wire batch refresh required')
    root = Path(root).resolve()
    contexts, definition = inputs(root)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(definition)).hexdigest()
    cache = root / 'knowledge/wire-batch-cache-11320' / (key + '.json')
    if cache.is_file() and not refresh:
        pointer = json.loads(cache.read_bytes())
        path = Path(pointer['report']).resolve()
        if (not path.is_relative_to(root / 'knowledge/wire-batch-verified-11320')
                or path.name != 'manifest.json' or path.parent.name != pointer['sha256']
                or digest(path) != pointer['sha256']):
            raise ValueError('Wire batch cached report changed')
        result = json.loads(path.read_bytes())
        validate_batch(result, contexts, definition, root)
        if inputs(root)[1] != definition:
            raise ValueError('Wire batch cache inputs changed')
        return path, result, True
    with locked(root, key):
        if cache.is_file() and not refresh:
            return run(root)
        reports = {}
        for name, (tool, _, _, _) in COMPONENTS.items():
            report = load(tool).verify(contexts[name], root)
            validate(name, report, contexts[name], root, definition)
            reports[name] = report
        if inputs(root)[1] != definition:
            raise ValueError('Wire batch inputs changed during replay')
        result = dict(schema=1, source_sha256=SHA, definition=definition, reports=reports,
            native_case_executions=559, network_used=False, profile_activated=False,
            runtime_activated=False, live_verified=False,
            limits=['Bounded UTF-8/string/archive and whole Version/Login wire bodies only.',
                'Allocator/free/memcpy/security remain fixtures; archive growth is rejected.',
                'No closed_shape admission, source preparation, framing, response handling or online compatibility.'])
        validate_batch(result, contexts, definition, root)
        path = workflow.snapshot(root, 'wire-batch-verified-11320', result)
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
