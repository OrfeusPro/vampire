"""Verify and cache current Time task execution over exact QuestTask rows."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re

from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/quest-time-current.json'
RECIPE = 'quest-time-current-v1'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
REPLAY = 'replay-quest-time-current-v1'
CATALOG = HERE / 'knowledge/native-contexts/quest-mixed-current.json'
TASKS = (110110010, 110110020, 110110030, 110110035, 110110040,
         110110050, 110110060, 110110080, 110110090, 110110100)
TIME_INDEXES = (0, 1, 3, 9)
LIMITS = [
    'Source CSV order supplies fixture indexes for the four Time rows; no live task object is read.',
    'Current native Time lifecycle is executed with explicit model, JSON and engine providers.',
    'The replay checks the local completion and pending request boundaries. It does not produce an actual actor transform.',
    'The 1810 action, 1811 confirmation and live quest progression are outside this proof.',
]
TOOLS = (
    'verify-quest-time-current', REPLAY, 'verify-quest-loader-current',
    'native-request-harness-11316', 'build-native-entry-code', 'extract-native-enums',
    'update-bindings', 'research-workflow', 'knowledge-index', 'audit-client-release',
    'native-publication-v2',
)


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(ok, message):
    if not ok:
        raise ValueError('Quest Time proof: ' + message)


def read_rows(raw):
    selected = [row for row in csv.DictReader(io.StringIO(raw.decode('utf-8-sig'), newline=''))
                if row['QuestInfoId'] == '110110']
    require(tuple(int(row['Id']) for row in selected) == TASKS
            and all(not row['ServerServiceGroupId'] for row in selected),
            'quest task order or service group differs')
    rows = []
    for index in TIME_INDEXES:
        row = selected[index]
        params = json.loads(row['Param'])
        require(row['Type'] == '6' and params == {'type': 'Time', 'seconds': 0.1}
                and type(params['seconds']) is float, 'Time parameters differ')
        rows.append(dict(task_id=int(row['Id']), index=index, seconds=params['seconds'], param=row['Param']))
    return rows


def definition(index, root, context_path):
    common = load('verify-quest-loader-current')
    context_path = Path(context_path).resolve()
    raw_context = common.read_bounded(context_path, 128 * 1024)
    context = json.loads(raw_context)
    require(context.get('source_sha256') == SOURCE, 'context source differs')
    catalog_raw = common.read_bounded(CATALOG, 128 * 1024)
    catalog = json.loads(catalog_raw)
    require(catalog.get('source_sha256') == SOURCE, 'catalog source differs')
    baseline = common.document(catalog['csv_baseline'], root, 'knowledge/resource-named-baselines-v1')
    archive = (Path(index.INSTALL).resolve().parents[2]
               / 'Saved/PersistentDownloadDir/Patch/Install/pakchunk1-Windows.pak').resolve()
    require(baseline.get('schema') == 1 and baseline.get('recipe') == 'named-table-baselines-v1'
            and Path(baseline['source']['archive_key']).resolve() == archive
            and baseline['source']['sha256'] == catalog['archive_sha256'],
            'named archive identity differs')
    pointer = catalog['tables']['quest_task']
    blob = Path(pointer['path']).resolve()
    matches = [row for row in baseline['tables']
               if row.get('canonical_path') == 'ProjectRED/Content/RED/Data/CSV/QuestTask.csv']
    require(re.fullmatch('[a-f0-9]{64}', pointer['sha256'])
            and blob == root / 'knowledge/resource-csv-blobs-v3' / (pointer['sha256'] + '.csv')
            and len(matches) == 1 and matches[0]['state'] == 'verified_payload'
            and Path(matches[0]['file']).resolve() == blob and matches[0]['sha256'] == pointer['sha256'],
            'named QuestTask identity differs')
    body = common.read_bounded(blob, 8 * 1024 * 1024)
    require(hashlib.sha256(body).hexdigest() == pointer['sha256'], 'QuestTask SHA differs')
    rows = read_rows(body)

    source = root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'
    files = {str(source): SOURCE, str(context_path): hashlib.sha256(raw_context).hexdigest(),
             str(CATALOG): hashlib.sha256(catalog_raw).hexdigest(),
             str(archive): catalog['archive_sha256'], str(blob): pointer['sha256'],
             str(Path(catalog['csv_baseline']['path']).resolve()): catalog['csv_baseline']['sha256']}
    files.update({str(HERE / (name + '.py')): common.digest(HERE / (name + '.py')) for name in TOOLS})
    exports = {}
    for run, sha in context['exports'].items():
        require(re.fullmatch('run-[0-9a-f]+', run) and re.fullmatch('[a-f0-9]{64}', sha),
                'export pointer differs')
        exports[str(root / 'ghidra/request-exports' / SOURCE / run / 'details.json')] = sha
    files.update(exports)
    runtime = {str(path): common.digest(path)
               for path in index.extension('native-publication-v2').runtime_files()}
    require(bool(runtime), 'runtime identity missing')
    files.update(runtime)
    return context, rows, dict(source_sha256=SOURCE, inputs=files, runtime_inputs=runtime,
        source=dict(path=str(archive), sha256=catalog['archive_sha256']), table=pointer,
        exports=exports)


def validate(report, selected, context, rows):
    require(report.get('schema') == 1 and report.get('recipe') == RECIPE
            and report.get('source_sha256') == SOURCE and report.get('definition') == selected
            and report.get('native_execution') is True and report.get('limits') == LIMITS
            and all(report.get(key) is False for key in (
                'network_used', 'runtime_admitted', 'live_step_verified', 'actor_vector_verified')),
            'receipt scope differs')
    load(REPLAY).validate(report['result'], context, rows)


def verify(*, root=ROOT, context_path=CONTEXT):
    index = load('knowledge-index').api()
    common = load('verify-quest-loader-current')
    workflow = index.extension('research-workflow')
    root = Path(root).resolve()
    context, rows, selected = definition(index, root, context_path)
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    common.barrier(selected['inputs'])
    if cache.is_file():
        pointer = json.loads(common.read_bounded(cache, 8192))
        report = common.document(pointer, root, 'code-clues/' + RECIPE, budget=2 * 1024 * 1024)
        validate(report, selected, context, rows)
        common.barrier(selected['inputs'])
        return dict(pointer, report=pointer['path'], reused=True)
    result = load(REPLAY).run(index, root, context, rows)
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected,
                  result=result, limits=LIMITS, native_execution=True, network_used=False,
                  runtime_admitted=False, live_step_verified=False, actor_vector_verified=False)
    validate(report, selected, context, rows)
    common.barrier(selected['inputs'])
    path = index.extension('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    pointer = dict(path=str(path), sha256=common.digest(path))
    workflow.atomic(cache, workflow.canonical(pointer))
    return dict(pointer, report=str(path), reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(root=args.root)))
