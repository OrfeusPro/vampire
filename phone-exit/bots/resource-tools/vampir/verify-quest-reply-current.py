"""Replay current 1811 wire and handler with an immutable offline proof."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/quest-reply-current.json'
RECIPE = 'quest-reply-current-v1'
SHA = re.compile('[a-f0-9]{64}')
LIMITS = [
    'Native receive executes outer/nested construction and readers. Archive primitive reads are bounded fixtures.',
    'Registration is a static byte window. Handler, result gate, wrapper and application dispatch execute.',
    'Settings, model record lookup, projection, key construction, virtual application and error presentation use fixtures.',
    'No real task mutation, server correlation, network use or runtime admission is established.',
]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError('Quest reply: ' + reason)


def barrier(inputs):
    require(all(digest(path) == expected for path, expected in inputs.items()), 'input SHA differs')


def definition(index, root, context_path):
    context_path = Path(context_path).resolve()
    raw = context_path.read_bytes()
    context = json.loads(raw)
    sha = context['source_sha256']
    require(context['schema'] == 1 and context['recipe'] == RECIPE and SHA.fullmatch(sha), 'context differs')
    roles = context['roles']
    require(set(roles) == {'constructor', 'reader', 'nested_reader', 'handler', 'gate', 'wrapper', 'application'}
            and len(set(roles.values())) == len(roles), 'role declaration differs')
    names = ('quest-reply-cases-v1', 'native-request-harness-11316', 'build-native-entry-code',
             'extract-native-enums', 'update-bindings', 'native-publication-v2',
             'research-workflow', 'audit-client-release', 'knowledge-index')
    inputs = {str(path): digest(path) for path in (Path(__file__).resolve(), *(HERE / (name + '.py') for name in names))}
    inputs[str(context_path)] = hashlib.sha256(raw).hexdigest()
    runtime = {str(path): digest(path) for path in index.extension('native-publication-v2').runtime_files()}
    require(runtime, 'runtime identity missing')
    inputs.update(runtime)
    source = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
    inputs[str(source)] = sha
    require(1 <= len(context['exports']) <= 4, 'export budget exceeded')
    for run, expected in context['exports'].items():
        require(re.fullmatch('run-[0-9a-f]+', run) and SHA.fullmatch(expected), 'export pointer differs')
        path = root / 'ghidra/request-exports' / sha / run / 'details.json'
        inputs[str(path)] = expected
    return context, dict(source_sha256=sha, inputs=inputs, runtime_inputs=runtime)


def validate(cases, report, selected):
    require(report.get('schema') == 1 and report.get('recipe') == RECIPE
            and report.get('source_sha256') == selected['source_sha256']
            and report.get('definition') == selected and report.get('packet_id') == 1811
            and report.get('wire_bytes') == 30 and report.get('native_execution') is True
            and all(report.get(key) is False for key in ('runtime_admitted', 'network_used', 'action_confirmed',
                                                        'applied_to_local_task', 'registration_executed'))
            and report.get('limits') == LIMITS, 'receipt scope differs')
    result = report.get('result', {})
    require(result.get('wire') == [cases.expected_wire(*case) for case in cases.wire_matrix()], 'wire matrix differs')
    require(result.get('applications') == [cases.expected_application(*case) for case in cases.application_matrix()],
            'application matrix differs')


def verify(*, root=ROOT, context_path=CONTEXT):
    index = load('knowledge-index').api()
    root = Path(root).resolve()
    context, selected = definition(index, root, context_path)
    cases = index.extension('quest-reply-cases-v1')
    workflow = index.extension('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    barrier(selected['inputs'])
    if cache.is_file():
        pointer = index.read_json(cache)
        path = Path(pointer['path']).resolve()
        require(SHA.fullmatch(pointer['sha256'])
                and path == root / 'code-clues' / RECIPE / pointer['sha256'] / 'manifest.json', 'receipt path differs')
        with path.open('rb') as stream:
            raw = stream.read(2 * 1024 * 1024 + 1)
        require(len(raw) <= 2 * 1024 * 1024 and hashlib.sha256(raw).hexdigest() == pointer['sha256'], 'receipt SHA differs')
        validate(cases, json.loads(raw), selected)
        barrier(selected['inputs'])
        return dict(report=str(path), sha256=pointer['sha256'], reused=True)
    result = cases.run(index, root, context)
    report = dict(schema=1, recipe=RECIPE, source_sha256=selected['source_sha256'], definition=selected,
                  packet_id=1811, wire_bytes=30, native_execution=True, result=result,
                  runtime_admitted=False, network_used=False, action_confirmed=False, applied_to_local_task=False,
                  registration_executed=False, limits=LIMITS)
    validate(cases, report, selected)
    barrier(selected['inputs'])
    path = index.extension('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    pointer = dict(path=str(path), sha256=digest(path))
    workflow.atomic(cache, workflow.canonical(pointer))
    return dict(report=str(path), sha256=pointer['sha256'], reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(root=args.root), ensure_ascii=False))
