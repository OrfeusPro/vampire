"""Bounded current QuestTask CSV loading, Russian override and native projection."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE/'knowledge/native-contexts/quest-loader-current.json'
RECIPE = 'quest-loader-current-v1'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
SHA = re.compile('[a-f0-9]{64}')
TOOLS = (
    'verify-quest-loader-current', 'replay-quest-loader-current-v1',
    'native-request-harness-11316', 'build-native-entry-code',
    'build-object-zero-init-code', 'extract-native-enums', 'audit-client-release',
    'knowledge-index', 'research-workflow', 'native-publication-v2', 'update-bindings',
)
LIMITS = [
    'Whole current main/Russian loaders create six source records and their group arrays in bounded fixture-backed storage.',
    'Thirty-six native projections read those same loaded records in forward/reverse input order; no Python-seeded task array is used.',
    'File/header/string/storage/hash/settings providers remain fixtures; only the six selected empty service groups are executed.',
    'The complete catalogue, nonempty service policy, active locale/settings and selected task lifecycle are not verified.',
    'No runtime order admission, active task, corrected actor position, outgoing action or live quest mutation is established.',
]
FALSE_FIELDS = ('runtime_admitted', 'network_used', 'active_task_verified',
    'ordered_catalog_verified', 'action_admitted', 'model_applied_online')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(ok, why):
    if not ok:
        raise ValueError('Quest loader: '+why)


def barrier(inputs):
    require(all(digest(name) == expected for name, expected in inputs.items()), 'input SHA differs')


def read_bounded(path, budget):
    with Path(path).open('rb') as stream:
        raw = stream.read(budget+1)
    require(len(raw) <= budget, 'JSON budget exceeded')
    return raw


def document(pointer, root, category, budget=8*1024*1024):
    require(isinstance(pointer, dict) and set(pointer) == {'path', 'sha256'}
        and SHA.fullmatch(str(pointer.get('sha256'))), 'receipt pointer differs')
    path = Path(pointer['path']).resolve()
    require(path == root/category/pointer['sha256']/'manifest.json', 'receipt path differs')
    raw = read_bounded(path, budget)
    require(hashlib.sha256(raw).hexdigest() == pointer['sha256'], 'receipt SHA differs')
    return json.loads(raw)


def crt_path():
    directory = ctypes.create_unicode_buffer(32768)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    require(0 < kernel.GetSystemDirectoryW(directory, len(directory)) < len(directory),
        'system directory unavailable')
    return (Path(directory.value)/'ucrtbase.dll').resolve()


def crt_locale(path):
    crt = ctypes.CDLL(str(path))
    crt.setlocale.argtypes = [ctypes.c_int, ctypes.c_char_p]
    crt.setlocale.restype = ctypes.c_char_p
    value = crt.setlocale(0, None)
    require(value is not None, 'CRT locale unavailable')
    return value.decode('utf-8')


def verify_inputs(selected):
    barrier(selected['inputs'])
    crt = selected['system_runtime']
    require(crt_locale(crt['path']) == crt['locale'], 'CRT locale changed')


def definition(index, root, context_path):
    context_path = Path(context_path).resolve()
    raw = read_bounded(context_path, 128*1024)
    context = json.loads(raw)
    require(context.get('schema') == 1 and context.get('recipe') == RECIPE
        and context.get('source_sha256') == SOURCE
        and set(context) == {'schema', 'recipe', 'source_sha256', 'exports', 'functions',
            'leaves', 'addresses', 'task_ids', 'csv', 'override_csv', 'limits',
            'csv_baseline', 'archive_sha256'}, 'context scope differs')
    require(1 <= len(context['functions']) <= 24
        and len(set(context['functions'])) == len(context['functions'])
        and 1 <= len(context['exports']) <= 12 and len(context['leaves']) <= 20
        and 1 <= len(context['addresses']) <= 128
        and len(context['task_ids']) == 6 and len(set(context['task_ids'])) == 6,
        'execution budget differs')
    source = root/'client-code-snapshots'/SOURCE/'ProjectRED-Win64-Shipping.exe'
    inputs = {str(context_path): hashlib.sha256(raw).hexdigest(), str(source): SOURCE}
    for name in TOOLS:
        path = (HERE/(name+'.py')).resolve()
        inputs[str(path)] = digest(path)
    exports = {}
    for run, expected in context['exports'].items():
        require(re.fullmatch('run-[0-9a-f]+', run) and SHA.fullmatch(str(expected)),
            'export pointer differs')
        exports[str(root/'ghidra/request-exports'/SOURCE/run/'details.json')] = expected
    inputs.update(exports)
    baseline = document(context['csv_baseline'], root, 'knowledge/resource-named-baselines-v1')
    require(baseline.get('schema') == 1 and baseline.get('recipe') == 'named-table-baselines-v1'
        and SHA.fullmatch(str(context['archive_sha256']))
        and baseline['source']['sha256'] == context['archive_sha256'], 'resource baseline differs')
    archive = (Path(index.INSTALL).resolve().parents[2]
        /'Saved/PersistentDownloadDir/Patch/Install/pakchunk1-Windows.pak').resolve()
    require(Path(baseline['source']['archive_key']).resolve() == archive,
        'resource baseline belongs to another archive')
    inputs[str(archive)] = context['archive_sha256']
    inputs[str(Path(context['csv_baseline']['path']).resolve())] = context['csv_baseline']['sha256']
    for role, canonical in (
            ('csv', 'ProjectRED/Content/RED/Data/CSV/QuestTask.csv'),
            ('override_csv', 'ProjectRED/Content/RED/Data/CSV/L10N/ru/QuestTask_Name.csv')):
        pointer = context[role]
        require(isinstance(pointer, dict) and set(pointer) == {'path', 'sha256'}
            and SHA.fullmatch(str(pointer.get('sha256'))), role+' pointer differs')
        blob = Path(pointer['path']).resolve()
        require(blob == root/'knowledge/resource-csv-blobs-v3'/(pointer['sha256']+'.csv'),
            role+' path differs')
        rows = [row for row in baseline['tables'] if row.get('canonical_path') == canonical]
        require(len(rows) == 1 and rows[0].get('state') == 'verified_payload'
            and Path(rows[0]['file']).resolve() == blob and rows[0]['sha256'] == pointer['sha256'],
            role+' named resource differs')
        inputs[str(blob)] = pointer['sha256']
    runtime = {str(Path(path).resolve()): digest(path)
        for path in index.extension('native-publication-v2').runtime_files()}
    crt = crt_path()
    runtime[str(crt)] = digest(crt)
    require(all(name not in inputs or inputs[name] == expected for name, expected in runtime.items()),
        'runtime input conflicts with retained inputs')
    inputs.update(runtime)
    return context, dict(source_sha256=SOURCE, inputs=inputs, runtime_inputs=runtime,
        context=dict(path=str(context_path), sha256=inputs[str(context_path)]),
        source=dict(path=str(archive), sha256=context['archive_sha256']),
        system_runtime=dict(path=str(crt), sha256=runtime[str(crt)], locale=crt_locale(crt)),
        exports=exports, task_ids=context['task_ids'], root_functions=context['functions'])


def validate(report, selected, context=None):
    require(isinstance(selected, dict) and selected.get('source_sha256') == SOURCE
        and report.get('schema') == 1 and report.get('recipe') == RECIPE
        and report.get('source_sha256') == SOURCE and report.get('definition') == selected
        and report.get('native_execution') is True and report.get('limits') == LIMITS
        and all(report.get(key) is False for key in FALSE_FIELDS), 'receipt scope differs')
    result = report.get('result', {})
    require(result.get('source_sha256') == SOURCE
        and result.get('tool_sha256') == selected['inputs'][str((HERE/'replay-quest-loader-current-v1.py').resolve())]
        and result.get('context_sha256') == selected['context']['sha256'], 'native result provenance differs')
    exports = result.get('exports')
    require(isinstance(exports, list) and len(exports) == len(selected['exports'])
        and all(isinstance(row, dict) and set(row) == {'path', 'sha256'}
            and isinstance(row['path'], str) for row in exports)
        and {str(Path(row['path']).resolve()): row['sha256'] for row in exports} == selected['exports'],
        'native result exports differ')
    runtime = result.get('system_runtime')
    require(isinstance(runtime, dict) and set(runtime) == {'path', 'sha256', 'locale'}
        and isinstance(runtime['path'], str)
        and dict(runtime, path=str(Path(runtime['path']).resolve())) == selected['system_runtime'],
        'native result CRT or locale differs')
    load('replay-quest-loader-current-v1').validate(result, context)


def verify(*, root=ROOT, context_path=CONTEXT):
    index = load('knowledge-index').api()
    root = Path(root).resolve()
    context, selected = definition(index, root, context_path)
    workflow = index.extension('research-workflow')
    cache = root/'knowledge'/(RECIPE+'-cache')/(hashlib.sha256(workflow.canonical(selected)).hexdigest()+'.json')
    verify_inputs(selected)
    if cache.is_file():
        pointer = json.loads(read_bounded(cache, 4096))
        report = document(pointer, root, 'code-clues/'+RECIPE)
        validate(report, selected, context)
        verify_inputs(selected)
        return dict(report=pointer['path'], sha256=pointer['sha256'], reused=True)
    _, result = load('replay-quest-loader-current-v1').run(context_path, root=root)
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected,
        result=result, native_execution=True, limits=LIMITS, **{key: False for key in FALSE_FIELDS})
    validate(report, selected, context)
    verify_inputs(selected)
    path = index.extension('audit-client-release').save_snapshot(root/'code-clues'/RECIPE, report)
    pointer = dict(path=str(path), sha256=digest(path))
    workflow.atomic(cache, workflow.canonical(pointer))
    return dict(report=str(path), sha256=pointer['sha256'], reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(root=args.root), ensure_ascii=False))
