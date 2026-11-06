"""One cached current CharacterList/WaitingEnd package; never network admission.

The generated harness is callable only through an exact material/scope guard.
The historical harness, six scenario bodies and all ordinary guards are retained;
only the source-specific budget block and registration/gate adapter are replaced.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys
import time

HERE = Path(__file__).resolve().parent
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
BASELINE = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
RECIPE = 'character-list-current-bounded-v1'
NAMES = ('waiting-end', 'character-list-envelope', 'character-record',
         'character-extensions', 'character-list-records', 'character-list-handler')
EXPECTED = {'waiting-end': {'cases': 16, 'fallback': 8},
    'character-list-envelope': {'cases': 24, 'truncated': 38, 'failures': 7},
    'character-record': {'cases': 128, 'truncated': 201, 'failures': 128, 'boundaries': 2},
    'character-list-records': {'cases': 32, 'truncated': 291, 'failures': 154, 'multi_truncated': 5},
    'character-list-handler': {'cases': 101}}


def load(name, path=None):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path or HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked(pointer, root, category):
    path = Path(pointer['path']).resolve()
    if (set(pointer) != {'path', 'sha256'} or path.name != 'manifest.json'
            or path.parent.parent != Path(root).resolve() / 'knowledge' / category
            or path.parent.name != pointer['sha256'] or digest(path) != pointer['sha256']
            or path.stat().st_size > 32 * 1024 * 1024):
        raise ValueError('Current CharacterList immutable pointer differs: ' + category)
    return json.loads(path.read_bytes())


def check_inputs(inputs):
    if not isinstance(inputs, dict) or not inputs:
        raise ValueError('Current CharacterList input set is empty')
    for name, sha in inputs.items():
        if not Path(name).is_absolute() or digest(name) != sha:
            raise ValueError('Current CharacterList input changed: ' + Path(name).name)


def make_harness(context, exports, functions, leaves=None, root=None):
    """Admit only an exact generated current component to the offline emulator."""
    root = Path(root or 'F:/PhoneExit Resources/Vampir').resolve()
    if context.get('source_sha256') != SOURCE or context.get('native_admission'):
        raise ValueError('Current CharacterList harness source/admission differs')
    pointer = context.get('current_character_scope', {})
    if set(pointer) != {'path', 'sha256', 'name'} or pointer['name'] not in NAMES:
        raise ValueError('Current CharacterList scope/name differs')
    scope = checked({k: pointer[k] for k in ('path', 'sha256')}, root, 'character-list-current-scopes')
    if (scope.get('recipe') != 'character-list-current-generated' or scope.get('source_sha256') != SOURCE
            or scope.get('baseline_sha256') != BASELINE or set(scope.get('scopes', {})) != set(NAMES)
            or len(scope.get('roots', {})) != 40 or scope.get('runtime_admitted') is not False
            or scope.get('semantic_verification') is not False):
        raise ValueError('Current CharacterList generated scope boundary differs')
    check_inputs(scope['inputs'])
    name = pointer['name']
    selected = scope['scopes'][name]
    wanted = {int(at, 16) for at in selected['roots']}
    variants = ([{int(at, 16) for at in variant} for variant in selected['variants'].values()]
                if name == 'character-extensions' else [wanted])
    if (not 1 <= len(wanted) <= 34 or set(functions) not in variants
            or (leaves or {}) != {int(at, 16): value for at, value in selected['leaves'].items()}
            or not wanted <= {int(at, 16) for at in scope['roots'].values()}):
        raise ValueError('Current CharacterList exact root/leaf allowlist differs')
    harness = context.get('current_character_harness', {})
    if set(harness) != {'path', 'sha256'}:
        raise ValueError('Current CharacterList harness pointer differs')
    path = Path(harness['path']).resolve()
    if (path.parent.parent != root / 'knowledge/character-list-current-code' or path.name != 'native-harness.py'
            or digest(path) != harness['sha256']):
        raise ValueError('Current CharacterList generated harness changed')
    generated = json.loads((path.parent / (name + '.json')).read_bytes())
    if context != generated or exports != generated.get('exports') or not 1 <= len(exports) <= 10:
        raise ValueError('Current CharacterList context/export scope differs')
    # The source bytes / whole roots / calls / tables are checked again by the
    # retained harness and scenario verifier. This guard replaces only its
    # historical fixed-version budget whitelist, never its instruction fence.
    return load('character_list_current_harness', path).make_harness(
        context, exports, functions, leaves=leaves, root=root)


def validate_report(name, report):
    if (report.get('source_sha256') != SOURCE or report.get('network_used') is not False
            or report.get('profile_activated') is not False or not report.get('limits')):
        raise ValueError('Current CharacterList component boundary differs: ' + name)
    if name == 'character-extensions':
        counts = {part['kind']: {key: len(part[key]) for key in ('cases', 'truncated', 'failures')}
                  for part in report['components']}
        if counts != {'appearance': {'cases': 5, 'truncated': 58, 'failures': 42},
                      'optional': {'cases': 19, 'truncated': 201, 'failures': 94}}:
            raise ValueError('Current CharacterList extension coverage differs')
    elif {key: len(report[key]) for key in EXPECTED[name]} != EXPECTED[name]:
        raise ValueError('Current CharacterList scenario coverage differs: ' + name)


def materials(generated_path, root):
    generated_path, root = Path(generated_path).resolve(), Path(root).resolve()
    pointer = dict(path=str(generated_path), sha256=digest(generated_path))
    generated = checked(pointer, root, 'character-list-current-generated')
    if (generated.get('source_sha256') != SOURCE or generated.get('baseline_sha256') != BASELINE
            or generated.get('recipe') != 'character-list-current-generated'
            or set(generated.get('contexts', {})) != set(NAMES)
            or set(generated.get('verifiers', {})) != set(NAMES)
            or generated.get('runtime_admitted') is not False or generated.get('network_used') is not False
            or generated.get('semantic_verification') is not False):
        raise ValueError('Current CharacterList generated composition differs')
    check_inputs(generated['inputs'])
    for name, sha in generated['files'].items():
        path = Path(name).resolve()
        if path.parent.parent != root / 'knowledge/character-list-current-code' or digest(path) != sha:
            raise ValueError('Current CharacterList generated file changed')
    scope = checked(generated['scope'], root, 'character-list-current-scopes')
    if scope['inputs'] != generated['inputs']:
        raise ValueError('Current CharacterList generated scope inputs differ')
    for name in NAMES:
        context = Path(generated['contexts'][name]).resolve()
        verifier = Path(generated['verifiers'][name]).resolve()
        if (str(context) not in generated['files'] or str(verifier) not in generated['files']
                or context.name != name + '.json' or verifier.name != 'verify-' + name + '-context.py'):
            raise ValueError('Current CharacterList component paths differ')
    definition = dict(recipe=RECIPE, source_sha256=SOURCE, generated=pointer,
        python=platform.python_version(), executable=sys.executable,
        runtime=load('update-native-harness').runtime_inputs(), inputs=generated['inputs'], files=generated['files'])
    return generated, definition


def verify_report(report_path, *, root=Path('F:/PhoneExit Resources/Vampir'), workspace=HERE.parents[3]):
    """Revalidate exact materials and current cached output, without native replay."""
    if (Path(workspace).resolve() / 'phone-exit/bots/resource-tools/vampir').resolve() != HERE:
        raise ValueError('Current CharacterList verifier workspace differs')
    report_path, root = Path(report_path).resolve(), Path(root).resolve()
    report = checked(dict(path=str(report_path), sha256=digest(report_path)), root, 'character-list-current-bounded')
    if (report.get('recipe') != RECIPE or report.get('source_sha256') != SOURCE
            or report.get('method') != 'bounded_native' or report.get('semantic_verification') is not True
            or any(report.get(key) is not False for key in ('network_used', 'runtime_admitted', 'profile_activated', 'live_verified'))
            or set(report.get('reports', {})) != set(NAMES) or not report.get('limits')):
        raise ValueError('Current CharacterList report boundary differs')
    _, expected = materials(report['definition']['generated']['path'], root)
    if report['definition'] != expected:
        raise ValueError('Current CharacterList report material definition differs')
    for name, component in report['reports'].items():
        validate_report(name, component)
    return report


@contextmanager
def build_lock(root, key):
    path = root / 'knowledge/character-list-current-cache' / (key + '.lock')
    path.parent.mkdir(parents=True, exist_ok=True)
    owner = json.dumps(dict(pid=os.getpid(), key=key)).encode()
    try:
        with path.open('xb') as stream:
            stream.write(owner)
    except FileExistsError:
        raise ValueError('Current CharacterList package already has an owner; inspect PID/lock before retry') from None
    try:
        yield
    finally:
        if path.read_bytes() != owner:
            raise ValueError('Current CharacterList lock owner changed')
        path.unlink()


def run(generated_path, root, refresh=False):
    root = Path(root).resolve()
    generated, definition = materials(generated_path, root)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(definition)).hexdigest()
    cache = root / 'knowledge/character-list-current-cache' / (key + '.json')
    if cache.is_file() and not refresh:
        pointer = json.loads(cache.read_bytes())
        result = verify_report(pointer['path'], root=root)
        if digest(pointer['path']) != pointer['sha256']:
            raise ValueError('Current CharacterList cache pointer changed')
        if result.get('definition') != definition or set(result.get('reports', {})) != set(NAMES):
            raise ValueError('Current CharacterList cached definition differs')
        for name, report in result['reports'].items():
            validate_report(name, report)
        if materials(generated_path, root)[1] != definition:
            raise ValueError('Current CharacterList inputs changed while reading cache')
        return Path(pointer['path']), result, True
    with build_lock(root, key):
        if cache.is_file() and not refresh:
            return run(generated_path, root)
        reports, durations, executed, reused_components = {}, {}, [], []
        for name in NAMES:
            started = time.perf_counter()
            context = json.loads(Path(generated['contexts'][name]).read_bytes())
            component_key = hashlib.sha256(workflow.canonical(dict(definition=definition, component=name))).hexdigest()
            component_cache = root / 'knowledge/character-list-current-cache' / (component_key + '.json')
            if component_cache.is_file() and not refresh:
                component = checked(json.loads(component_cache.read_bytes()), root, 'character-list-current-component')
                if component.get('definition') != definition or component.get('name') != name:
                    raise ValueError('Current CharacterList component checkpoint differs')
                reports[name] = component['report']
                reused_components.append(name)
            else:
                reports[name] = load('character_list_current_' + name, Path(generated['verifiers'][name])).verify(context, root)
                validate_report(name, reports[name])
                component = dict(definition=definition, name=name, report=reports[name])
                component_path = workflow.snapshot(root, 'character-list-current-component', component)
                workflow.atomic(component_cache, workflow.canonical(dict(path=str(component_path), sha256=digest(component_path))))
                executed.append(name)
            validate_report(name, reports[name])
            durations[name] = round(time.perf_counter() - started, 6)
        if materials(generated_path, root)[1] != definition:
            raise ValueError('Current CharacterList inputs changed during execution')
        result = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=definition,
            reports=reports, durations=durations, executed_components=executed, reused_components=reused_components,
            method='bounded_native', semantic_verification=True,
            network_used=False, runtime_admitted=False, profile_activated=False, live_verified=False,
            limits=['Only current whole WaitingEnd, readers, nested collections and separate CharacterList handler scenarios executed.',
                'Storage, allocation/rehash/shallow copy, services, SDK/controller/UI/flow and external state remain explicit fixtures.',
                'The previously verified shared INPUT and result gate proof are reused; no old native matrix or Ghidra run is repeated.',
                'No shared reader-to-handler integration, account, server acceptance, character creation, socket or runtime admission.'])
        result = json.loads(json.dumps(result))
        path = workflow.snapshot(root, 'character-list-current-bounded', result)
        workflow.atomic(cache, workflow.canonical(dict(path=str(path), sha256=digest(path))))
        return path, result, False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--generated', type=Path, required=True)
    parser.add_argument('--refresh', action='store_true')
    args = parser.parse_args()
    path, result, reused = run(args.generated, args.root, args.refresh)
    print(json.dumps(dict(report=str(path), sha256=digest(path), components=len(result['reports']), reused=reused)))
