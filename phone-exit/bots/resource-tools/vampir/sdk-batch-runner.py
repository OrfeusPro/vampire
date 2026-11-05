"""Run one cached target SDK package with resumable component evidence.

Only declared generated SDK modules execute. Existing sessions and external
services are outside this offline runner.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import locale
import os
from pathlib import Path
import platform
import re
import sys
import time


HERE = Path(__file__).resolve().parent
POLICY = HERE / 'knowledge/sdk-batch-rules.json'
RECIPE = 'sdk-batch-native-v1'
COMPONENT = 'sdk-batch-component-native-v1'
SHA = re.compile('[0-9a-f]{64}')
ROLE_STEMS = dict(defaults='replay-sdk-defaults', override='replay-sdk-overrides',
    platform='replay-sdk-platform', start='replay-gmc2-base', url='replay-gmc2-url',
    headers='replay-gmc2-headers', geo='replay-gmc2-geo', nid_base='replay-nid-context',
    nid_helpers='replay-nid-primitives')
FOLDERS = dict(defaults='sdk-defaults', override='sdk-overrides', platform='sdk-platform',
    start='gmc2-base', url='gmc2-url', headers='gmc2-headers', geo='gmc2-geo',
    nid_base='nid-context', nid_helpers='nid-primitives')
TOOLS = ('sdk-batch-runner.py', 'update-profile.py', 'research-workflow.py',
    'update-native-harness.py', 'native-request-harness-11316.py',
    'build-native-entry-code.py', 'build-object-zero-init-code.py',
    'extract-native-enums.py', 'audit-client-release.py', 'requirements-native.txt')


def load_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load(name):
    return load_path(name.replace('-', '_'), HERE / (name + '.py'))


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def check_files(files):
    for name, expected in files.items():
        if (not Path(name).is_absolute() or not isinstance(expected, str)
                or not SHA.fullmatch(expected) or digest(name) != expected):
            raise ValueError('SDK native input changed: ' + name)


def declare(inputs, path, sha):
    name = str(Path(path).resolve())
    if name in inputs and inputs[name] != sha:
        raise ValueError('SDK native input declarations conflict: ' + name)
    inputs[name] = sha


def pointer(path):
    return dict(path=str(Path(path).resolve()), sha256=digest(path))


def owned_snapshot(folder, value, workflow):
    """The package owner serializes these writes; publish complete bytes atomically."""
    raw = workflow.canonical(value)
    path = folder / hashlib.sha256(raw).hexdigest() / 'manifest.json'
    if path.exists():
        if path.read_bytes() != raw:
            raise ValueError('Immutable SDK manifest differs')
    else:
        workflow.atomic(path, raw)
    return path


def document(root, value, category):
    if not isinstance(value, dict) or set(value) != {'path', 'sha256'}:
        raise ValueError('SDK native proof pointer differs')
    path = Path(value['path']).resolve()
    folder = (root / 'knowledge' / category).resolve()
    if (path.name != 'manifest.json' or path.parent.parent != folder
            or path.parent.name != value['sha256'] or not SHA.fullmatch(str(value['sha256']))):
        raise ValueError('SDK native proof category or digest path differs')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != value['sha256']:
        raise ValueError('SDK native proof content changed')
    return json.loads(raw)


def runtime():
    workflow = load('research-workflow')
    distributions = load('update-native-harness').runtime_inputs()
    if {name: row['version'] for name, row in distributions.items()} != {'capstone': '5.0.6', 'unicorn': '2.1.4'}:
        raise ValueError('SDK native analysis runtime differs')
    crt, = workflow.system_runtime_files(['ucrtbase.dll'])
    executable = Path(sys.executable).resolve()
    return dict(python=platform.python_version(), executable=str(executable),
        executable_sha256=digest(executable), distributions=distributions,
        crt=dict(path=str(crt), sha256=digest(crt), locale=locale.setlocale(locale.LC_ALL)))


@contextmanager
def owner(root):
    folder = root / 'knowledge' / RECIPE
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / 'owner.lock'
    with path.open('a+b') as stream:
        if stream.seek(0, os.SEEK_END) == 0:
            stream.write(b'0')
            stream.flush()
        stream.seek(0)
        if os.name == 'nt':
            import msvcrt
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise ValueError('SDK native package already has an owner') from None
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise ValueError('SDK native package already has an owner') from None
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def stem(name):
    return re.sub('-[0-9]+$', '', Path(name).stem)


def prepare(root, generation_path):
    generation_pointer = pointer(generation_path)
    generation = document(root, generation_pointer, 'sdk-batch-generated-v1')
    sha = generation.get('source_sha256')
    baseline = generation.get('baseline_sha256')
    if (generation.get('schema') != 1 or generation.get('recipe') != 'sdk-batch-generated-v1'
            or not isinstance(sha, str) or not SHA.fullmatch(sha)
            or not isinstance(baseline, str) or not SHA.fullmatch(baseline) or sha == baseline
            or generation.get('semantic_verification') is not False
            or generation.get('network_used') is not False or generation.get('profile_activated') is not False):
        raise ValueError('SDK generated package source or scope differs')
    generated = generation.get('generated_templates', {})
    files = generation.get('files', {})
    if (not isinstance(generated, dict) or len(generated) != 12
            or not isinstance(files, dict) or len(files) != 12 or set(generated.values()) != set(files)
            or len(set(generated.values())) != 12):
        raise ValueError('SDK generated template set differs')
    key = generation.get('generation_key')
    if not isinstance(key, str) or not SHA.fullmatch(key):
        raise ValueError('SDK generation key differs')
    directory = root / 'knowledge/sdk-batch-generated-code' / key
    for name, path in generated.items():
        if Path(name).name != name or not name.endswith('.py') or Path(path).resolve().parent != directory:
            raise ValueError('SDK generated source outside selected generation')
    names = {stem(name): name for name in generated}
    expected = set(ROLE_STEMS.values()) | {'replay-nid-result', 'audit-nid-result', 'nid-primitives'}
    if set(names) != expected:
        raise ValueError('SDK generated replay family differs')
    policy = json.loads(POLICY.read_bytes())
    cases = policy.get('cases', {})
    if (policy.get('schema') != 1 or policy.get('recipe') != 'sdk-batch-v1'
            or set(cases) != {names[name] for name in expected - {'audit-nid-result', 'nid-primitives'}}
            or any(type(count) is not int or count < 1 for count in cases.values())
            or sum(cases.values()) != 3667):
        raise ValueError('SDK native case policy differs')
    if not isinstance(generation.get('inputs'), dict) or not generation['inputs']:
        raise ValueError('SDK generated input declaration differs')
    inputs = dict(generation['inputs'])
    for name, value in files.items():
        declare(inputs, name, value)
    declare(inputs, generation_pointer['path'], generation_pointer['sha256'])
    declare(inputs, POLICY, digest(POLICY))
    for name in TOOLS:
        declare(inputs, HERE / name, digest(HERE / name))
    shared = HERE.parents[1] / 'vampir-shared/vampir_core'
    for name in ('sdk_config.py', 'gmc2_request.py'):
        declare(inputs, shared / name, digest(shared / name))
    for source in (sha, baseline):
        path = root / 'client-code-snapshots' / source / 'ProjectRED-Win64-Shipping.exe'
        if inputs.get(str(path)) != source:
            raise ValueError('SDK generated source is not pinned')
    check_files(inputs)
    definition = dict(schema=1, recipe=RECIPE, source_sha256=sha,
        generation=generation_pointer, files=dict(sorted(inputs.items())), runtime=runtime(), cases=cases)
    roles = {role: names[value] for role, value in ROLE_STEMS.items()}
    return generation, definition, roles, names['audit-nid-result']


def guard(definition):
    check_files(definition['files'])
    if runtime() != definition['runtime']:
        raise ValueError('SDK native runtime changed during processing')


def validate_report(root, report, template, count, generation, definition):
    sha = definition['source_sha256']
    expected_source = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
    if (not isinstance(report, dict) or report.get('schema') != 1 or report.get('source_sha256') != sha
            or Path(report.get('source', '')).resolve() != expected_source
            or report.get('network_ready', False) is not False
            or report.get('network_used', False) is not False
            or report.get('profile_activated', False) is not False
            or report.get('runtime_enabled', False) is not False
            or report.get('active_runtime_settings_verified', False) is not False):
        raise ValueError('SDK component source or offline scope differs: ' + template)
    if count:
        if not isinstance(report.get('cases'), list) or len(report['cases']) != count:
            raise ValueError('SDK component matrix count differs: ' + template)
        for case in report['cases']:
            if not isinstance(case, dict) or ('canaries_unchanged' in case and case['canaries_unchanged'] is not True):
                raise ValueError('SDK component case or canary differs: ' + template)
    elif len(report.get('bindings', [])) != 7:
        raise ValueError('SDK NID result audit binding set differs')
    evidence = report.get('evidence')
    dependencies = report.get('dependencies')
    if not evidence or not isinstance(dependencies, dict) or not dependencies or not report.get('limits'):
        raise ValueError('SDK component provenance is incomplete: ' + template)
    for item in evidence:
        path = Path(item['path']).resolve()
        if (not path.is_relative_to(root / 'ghidra/request-exports' / sha)
                or path.name != 'details.json' or digest(path) != item['sha256']):
            raise ValueError('SDK component export differs: ' + template)
    for name, expected in dependencies.items():
        path = (HERE / name).resolve()
        if (not path.is_relative_to(HERE) and generation['files'].get(str(path)) != expected
                or digest(path) != expected):
            raise ValueError('SDK component dependency differs: ' + template)
    helper = {'replay-gmc2-url': 'sdk_config.py', 'replay-gmc2-headers': 'gmc2_request.py'}.get(stem(template))
    if helper:
        path = HERE.parents[1] / 'vampir-shared/vampir_core' / helper
        if report.get('portable_helper_sha256') != definition['files'][str(path)]:
            raise ValueError('SDK portable comparison proof differs: ' + template)
    if stem(template) == 'replay-nid-primitives':
        if (report.get('native_primitives') is not True
                or {name: len(rows) for name, rows in report.get('primitive_cases', {}).items()}
                    != dict(numeric=112, channels=176)
                or report.get('primitive_evidence', {}).get('crt') != definition['runtime']['crt']):
            raise ValueError('SDK NID actual primitive coverage or CRT differs')


def component(root, generation, definition, template, count, progress, workflow):
    component_definition = dict(definition, recipe=COMPONENT, template=template, case_count=count)
    key = hashlib.sha256(workflow.canonical(component_definition)).hexdigest()
    cache = root / 'knowledge/sdk-batch-component-cache-v1' / (key + '.json')
    failure = root / 'knowledge/sdk-batch-component-failure-cache-v1' / (key + '.json')
    started = time.perf_counter()
    guard(definition)
    if failure.is_file():
        saved = json.loads(failure.read_bytes())
        attempt = document(root, saved, 'sdk-batch-component-failures-v1')
        if attempt.get('definition') != component_definition or attempt.get('state') != 'failed':
            raise ValueError('SDK component failure cache definition differs')
        raise ValueError('SDK component has a saved failure for unchanged inputs: ' + saved['path'])
    if cache.is_file():
        saved = json.loads(cache.read_bytes())
        wrapper = document(root, saved, COMPONENT)
        if (wrapper.get('schema') != 1 or wrapper.get('recipe') != COMPONENT
                or wrapper.get('definition') != component_definition
                or wrapper.get('runtime_admitted') is not False):
            raise ValueError('SDK cached component definition or scope differs')
        report = wrapper['report']
        validate_report(root, report, template, count, generation, definition)
        reused = True
    else:
        if progress:
            progress(dict(event='sdk_component', template=template, state='running'))
        try:
            path = Path(generation['generated_templates'][template])
            module = load_path('sdk_generated_' + path.stem.replace('-', '_'), path)
            report = module.replay(root=root) if count else module.audit(root=root)
            report = json.loads(json.dumps(report, ensure_ascii=False))
            validate_report(root, report, template, count, generation, definition)
            guard(definition)
        except Exception as error:
            guard(definition)
            attempt = dict(schema=1, recipe=COMPONENT, definition=component_definition,
                state='failed', error_type=type(error).__name__, reason=str(error)[:1000],
                runtime_admitted=False, network_used=False)
            failed = pointer(owned_snapshot(root / 'knowledge/sdk-batch-component-failures-v1', attempt, workflow))
            workflow.atomic(failure, workflow.canonical(failed))
            if progress:
                progress(dict(event='sdk_component', template=template, state='failed', report=failed['path']))
            raise
        wrapper = dict(schema=1, recipe=COMPONENT, definition=component_definition,
            report=report, runtime_admitted=False)
        saved = pointer(owned_snapshot(root / 'knowledge' / COMPONENT, wrapper, workflow))
        workflow.atomic(cache, workflow.canonical(saved))
        reused = False
    if progress:
        progress(dict(event='sdk_component', template=template, state='passed', cached=reused,
            cases=count, seconds=round(time.perf_counter() - started, 3)))
    return report, saved, reused


def publish(root, reports, roles, generation_pointer, definition, workflow):
    result = {}
    sha = definition['source_sha256']
    declared = ('sdk-batch-runner.py', 'knowledge/sdk-batch-rules.json',
                'update-profile.py', 'research-workflow.py', 'update-native-harness.py')
    for role, template in roles.items():
        report = dict(reports[template])
        report['dependencies'] = dict(report['dependencies'])
        for name in declared:
            report['dependencies'][name] = definition['files'][str(HERE / name)]
        report.update(sdk_generated_proof=generation_pointer, network_ready=False,
                      runtime_enabled=False, profile_activated=False)
        folder = FOLDERS[role] + '-generated-' + sha[:12]
        path = owned_snapshot(root / 'code-clues' / folder, report, workflow)
        result[role] = pointer(path)
    return result


def validate_aggregate(root, report, definition, generation, roles, audit_template):
    if (report.get('schema') != 1 or report.get('recipe') != RECIPE
            or report.get('definition') != definition or report.get('source_sha256') != definition['source_sha256']
            or report.get('native_case_executions') != 3667 or report.get('runtime_admitted') is not False
            or report.get('profile_activated') is not False or report.get('network_used') is not False
            or report.get('active_runtime_settings_verified') is not False
            or set(report.get('reports', {})) != set(definition['cases'])
            or set(report.get('components', {})) != set(definition['cases']) | {audit_template}
            or set(report.get('component_reports', {})) != set(roles)):
        raise ValueError('SDK cached aggregate definition or coverage differs')
    for template, saved in report['components'].items():
        count = definition['cases'].get(template, 0)
        wrapper = document(root, saved, COMPONENT)
        wanted = dict(definition, recipe=COMPONENT, template=template, case_count=count)
        if wrapper.get('definition') != wanted or wrapper.get('runtime_admitted') is not False:
            raise ValueError('SDK aggregate component proof differs')
        raw = report['nid_audit'] if template == audit_template else report['reports'][template]
        if wrapper.get('report') != raw:
            raise ValueError('SDK aggregate does not match component evidence')
        validate_report(root, raw, template, count, generation, definition)
    for role, saved in report['component_reports'].items():
        path = Path(saved['path']).resolve()
        folder = root / 'code-clues' / (FOLDERS[role] + '-generated-' + definition['source_sha256'][:12])
        if path.name != 'manifest.json' or path.parent.parent != folder or path.parent.name != saved['sha256']:
            raise ValueError('SDK component publication path differs')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != saved['sha256']:
            raise ValueError('SDK component publication changed')
        published = json.loads(raw)
        if (published.get('sdk_generated_proof') != definition['generation']
                or published.get('source_sha256') != definition['source_sha256']
                or published.get('cases') != report['reports'][roles[role]]['cases']):
            raise ValueError('SDK component publication evidence differs')
        validate_report(root, published, roles[role], definition['cases'][roles[role]], generation, definition)
    assembled = load('update-profile').assemble({role: report['reports'][name] for role, name in roles.items()})
    if assembled != report.get('profile_candidate'):
        raise ValueError('SDK cached profile candidate differs')


def invocation(root, report_path, performed, reused, seconds, workflow, progress):
    result = dict(schema=1, recipe='sdk-batch-native-invocation-v1', report=pointer(report_path),
        performed_cases=performed, cached_cases=reused, seconds=round(seconds, 3),
        network_used=False, runtime_admitted=False)
    path = owned_snapshot(root / 'knowledge/sdk-batch-native-invocations-v1', result, workflow)
    if progress:
        progress(dict(event='sdk_batch', state='passed', performed_cases=performed,
            cached_cases=reused, seconds=result['seconds'], invocation=str(path)))


def run(root, generation_path, progress=None):
    root = Path(root).resolve()
    started = time.perf_counter()
    workflow = load('research-workflow')
    with owner(root):
        generation, definition, roles, audit_template = prepare(root, generation_path)
        key = hashlib.sha256(workflow.canonical(definition)).hexdigest()
        cache = root / 'knowledge/sdk-batch-native-cache-v1' / (key + '.json')
        if cache.is_file():
            saved = json.loads(cache.read_bytes())
            report = document(root, saved, RECIPE)
            validate_aggregate(root, report, definition, generation, roles, audit_template)
            guard(definition)
            path = Path(saved['path'])
            invocation(root, path, 0, 3667, time.perf_counter() - started, workflow, progress)
            return path, report, True
        reports, components = {}, {}
        performed, reused = 0, 0
        for template, count in definition['cases'].items():
            raw, saved, cached = component(root, generation, definition, template, count, progress, workflow)
            reports[template] = raw
            components[template] = saved
            if cached:
                reused += count
            else:
                performed += count
        audit, saved, _ = component(root, generation, definition, audit_template, 0, progress, workflow)
        components[audit_template] = saved
        candidate = load('update-profile').assemble({role: reports[name] for role, name in roles.items()})
        guard(definition)
        publications = publish(root, reports, roles, definition['generation'], definition, workflow)
        report = dict(schema=1, recipe=RECIPE, source_sha256=definition['source_sha256'],
            definition=definition, reports=reports, nid_audit=audit, components=components,
            component_reports=publications, profile_candidate=candidate, native_case_executions=3667,
            primitive_cases=dict(numeric=112, channels=176), runtime_admitted=False,
            network_used=False, profile_activated=False, active_runtime_settings_verified=False,
            limits=['Declared native scenarios use synthetic SDK/storage/HTTP boundaries.',
                    'No actual startup settings, authentication or game connection is verified.'])
        validate_aggregate(root, report, definition, generation, roles, audit_template)
        guard(definition)
        path = owned_snapshot(root / 'knowledge' / RECIPE, report, workflow)
        workflow.atomic(cache, workflow.canonical(pointer(path)))
        invocation(root, path, performed, reused, time.perf_counter() - started, workflow, progress)
        return path, report, False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--generation', type=Path, required=True)
    args = parser.parse_args()
    path, report, cached = run(args.root, args.generation,
        progress=lambda event: print(json.dumps(event), flush=True))
    print(json.dumps(dict(report=str(path), cached=cached, source_sha256=report['source_sha256'])))
