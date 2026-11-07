"""Cache exact-source checks of the nonempty QuestTask service-group gate."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/quest-service-current.json'
RECIPE = 'quest-service-current-v1'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
REPLAY = 'replay-quest-service-current-v1'
SHA = re.compile('[a-f0-9]{64}')
ROOTS = ('0x145a4d700', '0x145bff820', '0x145c03670', '0x145bff6a0', '0x145bfefd0')
TABLES = {'quest_task': 'QuestTask.csv', 'server_group': 'ServerGroup.csv',
          'server_service_group': 'ServerServiceGroup.csv'}
TOOLS = (
    'verify-quest-service-current', 'verify-quest-loader-current', REPLAY,
    'replay-quest-loader-current-v1', 'native-request-harness-11316',
    'build-native-entry-code', 'build-object-zero-init-code', 'extract-native-enums',
    'audit-client-release', 'knowledge-index', 'research-workflow',
    'native-publication-v2', 'update-bindings',
)
LIMITS = [
    'Whole current gate, service and server table getters, policy and numeric phase lookup execute in a bounded emulator.',
    'Source CSV rows seed fixture maps. The region and server ID are explicit inputs; the TLS fixture represents already initialized managers.',
    'Engine string conversion, splitting, allocation and cleanup are bounded providers; numeric conversion uses the pinned Windows CRT.',
    'Exact QuestTask loader branch bytes bind the gate to the row skip decision. Mixed catalogue loading and array order require a separate replay.',
    'Active server settings, task state, runtime admission and gameplay remain outside this proof.',
]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(condition, message):
    if not condition:
        raise ValueError('Quest service policy: ' + message)


def definition(index, root, context_path):
    common = load('verify-quest-loader-current')
    context_path = Path(context_path).resolve()
    raw = common.read_bounded(context_path, 128 * 1024)
    context = json.loads(raw)
    require(set(context) == {'schema', 'recipe', 'source_sha256', 'exports', 'functions',
                             'leaves', 'tables', 'csv_baseline', 'archive_sha256', 'limits'}
            and context['schema'] == 1 and context['recipe'] == RECIPE
            and context['source_sha256'] == SOURCE and context['limits'] == LIMITS,
            'context scope differs')
    require(tuple(context['functions']) == ROOTS and 1 <= len(context['exports']) <= 5
            and set(context['leaves']) == {'0x1445f6010', '0x1445f1630'},
            'native scope differs')

    source = root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'
    inputs = {str(context_path): hashlib.sha256(raw).hexdigest(), str(source): SOURCE}
    for name in TOOLS:
        path = HERE / (name + '.py')
        inputs[str(path)] = common.digest(path)
    exports = {}
    for run, expected in context['exports'].items():
        require(re.fullmatch('run-[0-9a-f]+', run) and SHA.fullmatch(str(expected)),
                'export pointer differs')
        exports[str(root / 'ghidra/request-exports' / SOURCE / run / 'details.json')] = expected
    inputs.update(exports)

    baseline_pointer = context['csv_baseline']
    baseline = common.document(baseline_pointer, root, 'knowledge/resource-named-baselines-v1')
    archive = (Path(index.INSTALL).resolve().parents[2]
               / 'Saved/PersistentDownloadDir/Patch/Install/pakchunk1-Windows.pak').resolve()
    require(baseline.get('schema') == 1 and baseline.get('recipe') == 'named-table-baselines-v1'
            and Path(baseline['source']['archive_key']).resolve() == archive
            and SHA.fullmatch(str(context['archive_sha256']))
            and baseline['source']['sha256'] == context['archive_sha256'],
            'named tables belong to a different archive')
    inputs[str(archive)] = context['archive_sha256']
    inputs[str(Path(baseline_pointer['path']).resolve())] = baseline_pointer['sha256']
    require(set(context['tables']) == set(TABLES), 'table roles differ')
    for role, filename in TABLES.items():
        pointer = context['tables'][role]
        require(set(pointer) == {'path', 'sha256'} and SHA.fullmatch(str(pointer['sha256'])),
                'table pointer differs: ' + role)
        blob = Path(pointer['path']).resolve()
        rows = [row for row in baseline['tables']
                if row.get('canonical_path') == 'ProjectRED/Content/RED/Data/CSV/' + filename]
        require(blob == root / 'knowledge/resource-csv-blobs-v3' / (pointer['sha256'] + '.csv')
                and len(rows) == 1 and rows[0]['state'] == 'verified_payload'
                and Path(rows[0]['file']).resolve() == blob and rows[0]['sha256'] == pointer['sha256'],
                'named resource differs: ' + role)
        inputs[str(blob)] = pointer['sha256']

    crt = common.crt_path()
    runtime_paths = set(index.extension('native-publication-v2').runtime_files()) | {crt}
    runtime = {str(Path(path).resolve()): common.digest(path) for path in runtime_paths}
    require(all(name not in inputs or inputs[name] == expected for name, expected in runtime.items()),
            'runtime conflicts with retained inputs')
    inputs.update(runtime)
    return context, dict(source_sha256=SOURCE, inputs=inputs, runtime_inputs=runtime,
        context=dict(path=str(context_path), sha256=inputs[str(context_path)]),
        source=dict(path=str(archive), sha256=context['archive_sha256']), exports=exports,
        system_runtime=dict(path=str(crt), sha256=runtime[str(crt)], locale=common.crt_locale(crt)))


def validate(report, selected, context):
    common = load('verify-quest-loader-current')
    require(report.get('schema') == 1 and report.get('recipe') == RECIPE
            and report.get('source_sha256') == SOURCE and report.get('definition') == selected
            and report.get('native_execution') is True and report.get('limits') == LIMITS
            and all(report.get(key) is False for key in common.FALSE_FIELDS), 'receipt scope differs')
    result = report['result']
    require(result.get('source_sha256') == SOURCE
            and result.get('tool_sha256') == selected['inputs'][str(HERE / (REPLAY + '.py'))]
            and result.get('context_sha256') == selected['context']['sha256'], 'replay provenance differs')
    exports = result['exports']
    require(len(exports) == len(selected['exports'])
            and {str(Path(row['path']).resolve()): row['sha256'] for row in exports} == selected['exports'],
            'replay exports differ')
    runtime = result['system_runtime']
    require(dict(runtime, path=str(Path(runtime['path']).resolve())) == selected['system_runtime'],
            'replay CRT or locale differs')
    load(REPLAY).validate(result, context)


def verify(*, root=ROOT, context_path=CONTEXT):
    common = load('verify-quest-loader-current')
    index = load('knowledge-index').api()
    root = Path(root).resolve()
    context, selected = definition(index, root, context_path)
    workflow = index.extension('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    common.verify_inputs(selected)
    if cache.is_file():
        pointer = json.loads(common.read_bounded(cache, 4096))
        report = common.document(pointer, root, 'code-clues/' + RECIPE)
        validate(report, selected, context)
        common.verify_inputs(selected)
        return dict(report=pointer['path'], sha256=pointer['sha256'], reused=True)

    _, result = load(REPLAY).run(context_path, root=root)
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected,
                  result=result, native_execution=True, limits=LIMITS,
                  **{key: False for key in common.FALSE_FIELDS})
    validate(report, selected, context)
    common.verify_inputs(selected)
    path = index.extension('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    pointer = dict(path=str(path), sha256=common.digest(path))
    workflow.atomic(cache, workflow.canonical(pointer))
    return dict(report=str(path), sha256=pointer['sha256'], reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(root=args.root), ensure_ascii=False))
