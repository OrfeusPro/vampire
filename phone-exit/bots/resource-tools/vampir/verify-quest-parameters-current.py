"""Qualify current task parameter binding and numeric projection without gameplay."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/quest-parameters-current.json'
RECIPE = 'quest-parameters-current-v1'
SHA = re.compile('[a-f0-9]{64}')
LIMITS = [
    'Task parameter adapters and dispatcher execute with bounded allocation, JSON and callback fixtures.',
    'The final dialogue/task parser callbacks are boundaries, not an executed dialogue player.',
    'Numeric projection executes the native accessor and scalar reader; virtual TryGetNumber remains a fixture.',
    'String-to-number implementation, default scalar allocation and active task selection remain unverified.',
    'No current quest action provider, runtime action admission, received prompt or online result is established.',
]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError('Quest parameters: ' + message)


def barrier(inputs):
    require(all(digest(name) == expected for name, expected in inputs.items()), 'input SHA differs')


def definition(index, root, context_path):
    context_path = Path(context_path).resolve()
    raw = context_path.read_bytes()
    context = json.loads(raw)
    require(context.get('schema') == 1 and context.get('recipe') == RECIPE
            and isinstance(context.get('source_sha256'), str) and SHA.fullmatch(context['source_sha256'])
            and set(context) == {'schema', 'recipe', 'source_sha256', 'exports', 'binding', 'scalar'},
            'context scope differs')
    sha = context['source_sha256']
    source = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
    for key in ('binding', 'scalar'):
        selected = context[key]['native']
        require(selected['source_sha256'] == sha and Path(selected['source']).resolve() == source,
                key + ' source differs')
        require(1 <= len(selected['functions']) <= 12 and len(selected['fixtures']) <= 32
                and len(selected['leaves']) <= 16, key + ' execution budget differs')
    names = ('quest-param-binding-cases-v1', 'quest-param-scalar-cases-v1',
        'quest-tutorial-state-harness-v1', 'build-native-entry-code', 'update-bindings',
        'login-input-transfer-rules', 'quest-action-transfer-rules-v1', 'extract-native-enums',
        'version-system-transfer-rules', 'update-native-version-result', 'update-native-contexts',
        'native-publication-v2', 'research-workflow', 'audit-client-release', 'knowledge-index')
    files = {str(path.resolve()): digest(path) for path in
        (Path(__file__), *(HERE / (name + '.py') for name in names))}
    files[str(context_path)] = hashlib.sha256(raw).hexdigest()
    runtime = {str(path): digest(path) for path in index.extension('native-publication-v2').runtime_files()}
    require(runtime, 'runtime identity missing')
    files.update(runtime)
    files[str(source)] = sha
    require(1 <= len(context['exports']) <= 4, 'export budget differs')
    for run, expected in context['exports'].items():
        require(re.fullmatch('run-[0-9a-f]+', run) and SHA.fullmatch(expected), 'export pointer differs')
        path = root / 'ghidra/request-exports' / sha / run / 'details.json'
        files[str(path)] = expected
    return context, dict(source_sha256=sha, inputs=files, runtime_inputs=runtime)


def validate(report, selected):
    require(isinstance(selected,dict) and isinstance(selected.get('source_sha256'),str)
            and SHA.fullmatch(selected['source_sha256']), 'receipt definition differs')
    require(report.get('schema') == 1 and report.get('recipe') == RECIPE
            and report.get('source_sha256') == selected['source_sha256']
            and report.get('definition') == selected and report.get('native_execution') is True
            and all(report.get(name) is False for name in ('runtime_admitted', 'active_task_verified',
                'dialogue_started', 'skip_behavior_verified', 'network_used', 'class_string_conversion_verified'))
            and report.get('limits') == LIMITS and set(report.get('results', {})) == {'binding', 'scalar'},
            'receipt scope differs')
    load('quest-param-binding-cases-v1').validate(report['results']['binding'])
    load('quest-param-scalar-cases-v1').validate(report['results']['scalar'])


def verify(*, root=ROOT, context_path=CONTEXT):
    index = load('knowledge-index').api()
    root = Path(root).resolve()
    context, selected = definition(index, root, context_path)
    workflow = index.extension('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    barrier(selected['inputs'])
    if cache.is_file():
        pointer = index.read_json(cache)
        path = Path(pointer['path']).resolve()
        require(SHA.fullmatch(pointer['sha256'])
                and path == root / 'code-clues' / RECIPE / pointer['sha256'] / 'manifest.json',
                'receipt path differs')
        with path.open('rb') as stream:
            raw = stream.read(8 * 1024 * 1024 + 1)
        require(len(raw) <= 8 * 1024 * 1024 and hashlib.sha256(raw).hexdigest() == pointer['sha256'],
                'receipt SHA differs')
        validate(json.loads(raw), selected)
        barrier(selected['inputs'])
        return dict(report=str(path), sha256=pointer['sha256'], reused=True)
    exports = []
    for run in context['exports']:
        path = root / 'ghidra/request-exports' / context['source_sha256'] / run / 'details.json'
        with path.open('rb') as stream:
            raw = stream.read(32 * 1024 * 1024 + 1)
        require(len(raw) <= 32 * 1024 * 1024 and hashlib.sha256(raw).hexdigest() == context['exports'][run],
                'export changed or exceeded budget')
        exports.append(json.loads(raw))
    source = (root / 'client-code-snapshots' / context['source_sha256'] / 'ProjectRED-Win64-Shipping.exe').read_bytes()
    require(hashlib.sha256(source).hexdigest() == context['source_sha256'], 'source changed')
    results = {kind: load('quest-param-' + kind + '-cases-v1').execute(
        index, root, context[kind], exports, source) for kind in ('binding', 'scalar')}
    report = dict(schema=1, recipe=RECIPE, source_sha256=context['source_sha256'], definition=selected,
        native_execution=True, results=results, runtime_admitted=False, active_task_verified=False,
        dialogue_started=False, skip_behavior_verified=False, network_used=False,
        class_string_conversion_verified=False, limits=LIMITS)
    validate(report, selected)
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
