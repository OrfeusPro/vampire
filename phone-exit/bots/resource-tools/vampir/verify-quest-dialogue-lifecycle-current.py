"""Verify and cache bounded current Dialog completion and retry callbacks."""
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
CONTEXT = HERE / 'knowledge/native-contexts/quest-dialogue-lifecycle-current.json'
CATALOG = HERE / 'knowledge/native-contexts/quest-mixed-current.json'
RECIPE = 'quest-dialogue-lifecycle-current-v1'
REPLAY = 'replay-quest-dialogue-lifecycle-current-v1'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
TASKS = (110110010, 110110020, 110110030, 110110035, 110110040,
         110110050, 110110060, 110110080, 110110090, 110110100)
LIMITS = [
    'QuestTask CSV order supplies index 2 and ClassInfo 1 supplies DialogGroupId 11011110; no live object is read.',
    'Native scheduling, delayed and event callbacks execute with explicit engine, delegate and model fixtures.',
    'Playback, timer dispatch, dialogue move packets, current owner capability and online quest transition remain outside this proof.',
]
TOOLS = ('verify-quest-dialogue-lifecycle-current', REPLAY, 'verify-quest-loader-current',
         'native-request-harness-11316', 'build-native-entry-code', 'extract-native-enums',
         'update-bindings', 'research-workflow', 'knowledge-index', 'audit-client-release', 'native-publication-v2')


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(ok, message):
    if not ok:
        raise ValueError('Dialog lifecycle proof: ' + message)


def read_row(raw):
    rows = [row for row in csv.DictReader(io.StringIO(raw.decode('utf-8-sig'), newline=''))
            if row['QuestInfoId'] == '110110']
    require(tuple(int(row['Id']) for row in rows) == TASKS
            and all(not row['ServerServiceGroupId'] for row in rows), 'task order/service group differs')
    row = rows[2]
    params = json.loads(row['Param'])
    require(row['Type'] == '6' and set(params) == {'type', 'classBranch'} and params['type'] == 'Dialog'
            and type(params['classBranch']) is list, 'Dialog task type differs')
    selected = [branch for branch in params['classBranch'] if branch.get('classInfoId') == '1']
    require(selected == [dict(classInfoId='1', dialogGroupId=11011110)], 'ClassInfo 1 dialogue branch differs')
    return dict(task_id=110110030, quest_id=110110, index=2, class_info_id=1, dialog_group_id=11011110)


def definition(index, root, context_path):
    common = load('verify-quest-loader-current')
    context_path = Path(context_path).resolve()
    context_raw = common.read_bounded(context_path, 128 * 1024)
    context = json.loads(context_raw)
    require(context.get('schema') == 1 and context.get('recipe') == RECIPE
            and context.get('source_sha256') == SOURCE and context.get('roles') == load(REPLAY).ROLES,
            'context recipe/source/roles differ')
    catalog_raw = common.read_bounded(CATALOG, 128 * 1024)
    catalog = json.loads(catalog_raw)
    require(catalog.get('source_sha256') == SOURCE, 'catalog source differs')
    baseline = common.document(catalog['csv_baseline'], root, 'knowledge/resource-named-baselines-v1')
    archive = (Path(index.INSTALL).resolve().parents[2]
               / 'Saved/PersistentDownloadDir/Patch/Install/pakchunk1-Windows.pak').resolve()
    require(baseline.get('schema') == 1 and baseline.get('recipe') == 'named-table-baselines-v1'
            and Path(baseline['source']['archive_key']).resolve() == archive
            and baseline['source']['sha256'] == catalog['archive_sha256'], 'named archive identity differs')
    pointer = catalog['tables']['quest_task']
    blob = Path(pointer['path']).resolve()
    matches = [row for row in baseline['tables']
               if row.get('canonical_path') == 'ProjectRED/Content/RED/Data/CSV/QuestTask.csv']
    require(re.fullmatch('[a-f0-9]{64}', pointer['sha256'])
            and blob == root / 'knowledge/resource-csv-blobs-v3' / (pointer['sha256'] + '.csv')
            and len(matches) == 1 and matches[0]['state'] == 'verified_payload'
            and Path(matches[0]['file']).resolve() == blob and matches[0]['sha256'] == pointer['sha256'],
            'QuestTask provenance differs')
    body = common.read_bounded(blob, 8 * 1024 * 1024)
    require(hashlib.sha256(body).hexdigest() == pointer['sha256'], 'QuestTask SHA differs')
    row = read_row(body)
    source = root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'
    files = {str(source): SOURCE, str(context_path): hashlib.sha256(context_raw).hexdigest(),
             str(CATALOG): hashlib.sha256(catalog_raw).hexdigest(),
             str(archive): catalog['archive_sha256'], str(blob): pointer['sha256'],
             str(Path(catalog['csv_baseline']['path']).resolve()): catalog['csv_baseline']['sha256']}
    files.update({str(HERE / (name + '.py')): common.digest(HERE / (name + '.py')) for name in TOOLS})
    exports = {}
    require(type(context.get('exports')) is dict and 1 <= len(context['exports']) <= 12, 'export budget differs')
    for run, sha in context['exports'].items():
        require(re.fullmatch('run-[0-9a-f]+', run) and re.fullmatch('[a-f0-9]{64}', sha), 'export pointer differs')
        exports[str(root / 'ghidra/request-exports' / SOURCE / run / 'details.json')] = sha
    files.update(exports)
    runtime = {str(path): common.digest(path) for path in index.extension('native-publication-v2').runtime_files()}
    require(bool(runtime), 'runtime identity missing')
    files.update(runtime)
    return context, row, dict(source_sha256=SOURCE, inputs=files, runtime_inputs=runtime,
                             source=dict(path=str(archive), sha256=catalog['archive_sha256']),
                             table=pointer, exports=exports)


def validate(report, selected, context, row):
    require(report.get('schema') == 1 and report.get('recipe') == RECIPE
            and report.get('source_sha256') == SOURCE and report.get('definition') == selected
            and report.get('native_execution') is True and report.get('limits') == LIMITS
            and all(report.get(key) is False for key in
                    ('network_used', 'runtime_admitted', 'live_step_verified', 'dialogue_playback_verified')),
            'receipt scope differs')
    load(REPLAY).validate(report['result'], context, row)


def verify(*, root=ROOT, context_path=CONTEXT):
    index = load('knowledge-index').api()
    common = load('verify-quest-loader-current')
    workflow = index.extension('research-workflow')
    root = Path(root).resolve()
    context, row, selected = definition(index, root, context_path)
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    common.barrier(selected['inputs'])
    if cache.is_file():
        pointer = json.loads(common.read_bounded(cache, 8192))
        report = common.document(pointer, root, 'code-clues/' + RECIPE, budget=2 * 1024 * 1024)
        validate(report, selected, context, row)
        common.barrier(selected['inputs'])
        return dict(pointer, report=pointer['path'], reused=True)
    result = load(REPLAY).run(index, root, context, row)
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected,
                  result=result, limits=LIMITS, native_execution=True, network_used=False,
                  runtime_admitted=False, live_step_verified=False, dialogue_playback_verified=False)
    validate(report, selected, context, row)
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
