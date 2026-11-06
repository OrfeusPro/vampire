"""Cached current SHA Clock/Ping/bounded-world package; no network or admission."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
SHA = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
COMPONENTS = {
    'clock': ('replay-login-clock-current', 24),
    'producer': ('replay-login-ping-current', 36),
    'world': ('replay-world-entry-current', 201),
    'result': ('replay-ping-result-current', 36),
}
DEPENDENCIES = (
    'run-clock-world-current.py', 'generate-clock-world-current.py',
    'verify-clock-replay-source-current.py', 'verify-ping-world-source-current.py',
    'native-request-harness-11316.py', 'build-native-entry-code.py',
    'build-object-zero-init-code.py', 'extract-native-enums.py',
    'audit-launcher-shape-11318.py', 'knowledge-index.py', 'research-workflow.py',
    'audit-client-release.py', 'update-native-harness.py', 'requirements-native.txt',
    'knowledge/native-contexts/clock-world-current.json',
    'knowledge/native-contexts/clock-world-native-input-current.json',
)


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inputs(root=ROOT):
    root = Path(root).resolve()
    source = root / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe'
    if digest(source) != SHA:
        raise ValueError('Current Clock/world EXE changed')
    context = json.loads((HERE / 'knowledge/native-contexts/clock-world-current.json').read_bytes())
    if context['source_sha256'] != SHA:
        raise ValueError('Current Clock/world context source changed')
    paths = {HERE / name for name in DEPENDENCIES}
    paths.update(HERE / (tool + '.py') for tool, _ in COMPONENTS.values())
    for path, expected in context['generation_inputs'].items():
        if digest(path) != expected:
            raise ValueError('Current Clock/world generation input changed')
        paths.add(Path(path))
    for name in ('plan', 'native_input'):
        pointer = context[name]
        path = Path(pointer['path']).resolve()
        if not path.is_relative_to(root / 'knowledge') or digest(path) != pointer['sha256']:
            raise ValueError('Current Clock/world retained input changed')
        paths.add(path)
    native_input = json.loads((HERE / 'knowledge/native-contexts/clock-world-native-input-current.json').read_bytes())['native_input']
    if native_input['source_sha256'] != SHA:
        raise ValueError('Current Clock/world INPUT source changed')
    exports = {}
    for run, expected in dict(context['exports'], **native_input['exports']).items():
        path = root / 'ghidra/request-exports' / SHA / run / 'details.json'
        if digest(path) != expected or json.loads(path.read_bytes())['new_source_sha256'] != SHA:
            raise ValueError('Current Clock/world export changed')
        exports[str(path)] = expected
    return context, dict(source_sha256=SHA, python=platform.python_version(), executable=sys.executable,
                         files={str(p.resolve()): digest(p) for p in sorted(paths)}, exports=exports,
                         runtime=load('update-native-harness').runtime_inputs())


def validate_component(name, report):
    if (report.get('source_sha256') != SHA or report.get('network_used') is not False
            or report.get('profile_activated') is not False or not report.get('limits')
            or len(report.get('cases', [])) != COMPONENTS[name][1]):
        raise ValueError('Current Clock/world component scope changed')
    if name == 'clock' and report.get('lobby_cases') != []:
        raise ValueError('Old lobby handler must not enter current Clock package')
    if name == 'result' and len(report.get('short', [])) != 12:
        raise ValueError('Current Ping truncated coverage changed')


def verify_report(path, expected, definition, root=ROOT):
    root = Path(root).resolve()
    path = Path(path).resolve()
    if (not path.is_relative_to(root / 'knowledge/clock-world-current-verified')
            or path.name != 'manifest.json' or path.parent.name != expected or digest(path) != expected):
        raise ValueError('Current Clock/world cached report changed')
    report = json.loads(path.read_bytes())
    if (report.get('definition') != definition or report.get('source_sha256') != SHA
            or set(report.get('components', {})) != set(COMPONENTS)
            or report.get('network_used') is not False or report.get('profile_activated') is not False
            or report.get('runtime_admitted') is not False):
        raise ValueError('Current Clock/world cached composition changed')
    for name, pointer in report['components'].items():
        component = Path(pointer['path']).resolve()
        if (not component.is_relative_to(root / 'code-clues') or component.name != 'manifest.json'
                or component.parent.name != pointer['sha256'] or digest(component) != pointer['sha256']):
            raise ValueError('Current Clock/world component report changed')
        validate_component(name, json.loads(component.read_bytes()))
    return report


@contextmanager
def locked(root, key):
    path = root / 'knowledge/clock-world-current-cache' / (key + '.lock')
    path.parent.mkdir(parents=True, exist_ok=True)
    owner = json.dumps(dict(pid=os.getpid(), key=key)).encode()
    try:
        with path.open('xb') as stream:
            stream.write(owner)
    except FileExistsError:
        raise ValueError('Current Clock/world owned; inspect recorded PID before retry') from None
    try:
        yield
    finally:
        if path.read_bytes() != owner:
            raise ValueError('Current Clock/world owner changed')
        path.unlink()


def run(root=ROOT):
    root = Path(root).resolve()
    context, definition = inputs(root)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(definition)).hexdigest()
    cache = root / 'knowledge/clock-world-current-cache' / (key + '.json')
    if cache.is_file():
        pointer = json.loads(cache.read_bytes())
        report = verify_report(pointer['path'], pointer['sha256'], definition, root)
        if inputs(root)[1] != definition:
            raise ValueError('Current Clock/world cache inputs changed')
        return Path(pointer['path']), report, True
    with locked(root, key):
        if cache.is_file():
            return run(root)
        components = {}
        for name, (tool, _) in COMPONENTS.items():
            pointer = load(tool).verify(context['exports'])
            path = Path(pointer['report'])
            if digest(path) != pointer['sha256']:
                raise ValueError('New Clock/world component report changed')
            validate_component(name, json.loads(path.read_bytes()))
            components[name] = dict(path=str(path), sha256=pointer['sha256'])
        if inputs(root)[1] != definition:
            raise ValueError('Current Clock/world inputs changed during replay')
        report = dict(schema=1, recipe='clock-world-current-v1', source_sha256=SHA,
                      method='bounded_native', native_execution=True, definition=definition,
                      components=components, cases=297, short_prefixes=12,
                      network_used=False, profile_activated=False, runtime_admitted=False,
                      limits=['UTC backend/month length/local cache, engine/context/send/recovery are fixtures.',
                              'Reserve stops at opaque suffix; nested ID110/206 compatibility remains outside.',
                              'New lobby VersionResult belongs to its independent current proof.',
                              'No network, login/world acceptance, full engine or durable session is proved.'])
        path = workflow.snapshot(root, 'clock-world-current-verified', report)
        workflow.atomic(cache, workflow.canonical(dict(path=str(path), sha256=digest(path))))
        return path, report, False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    path, report, reused = run(args.root)
    print(json.dumps(dict(report=str(path), sha256=digest(path), reused=reused,
                          native_executed=not reused, cases=report['cases'], short_prefixes=report['short_prefixes'])))
