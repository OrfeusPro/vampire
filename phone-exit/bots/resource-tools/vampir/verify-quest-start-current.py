"""Source-bound manual QuestStart1803/1804 proof, normal on_update and immutable cache."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from itertools import product
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/quest-start-current.json'
RECIPE = 'quest-start-current-v1'
SHA = re.compile('[a-f0-9]{64}')
LIMITS = [
    'Whole current request constructor/writer/reader, outer result INPUT, selector0 producer and eligibility execute with explicit providers.',
    'Nested QuestData INPUT reuses the retained current1854 proof; the new outer-reader replay uses an explicit nested provider.',
    'Quest row, numeric named fields, pending requests, level, predecessor, conditions, model lookup and send are fixtures.',
    'Enqueue/UI and result handler linkage are source-checked whole exports/static windows; their engine effects are not executed here.',
    'This proof supports an explicit manual start attempt only; automatic task execution, corrected actor position and completion are separate.',
    'No network operation, runtime activation or online success is established by this offline proof.',
]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(ok, reason):
    if not ok:
        raise ValueError('QuestStart proof: ' + reason)


def barrier(inputs):
    require(all(digest(path) == sha for path, sha in inputs.items()), 'input SHA changed')


def definition(index, root, context_path):
    context_path = Path(context_path).resolve()
    context = json.loads(context_path.read_bytes())
    require(context['schema'] == 1 and context['recipe'] == RECIPE
            and SHA.fullmatch(context['source_sha256']), 'context identity')
    paths = [Path(__file__).resolve(), context_path, *(HERE / (name + '.py') for name in
        ('quest-start-cases-v1', 'native-request-harness-11316', 'build-native-entry-code',
         'extract-native-enums', 'update-bindings', 'research-workflow', 'knowledge-index',
         'audit-client-release', 'native-publication-v2'))]
    inputs = {str(path): digest(path) for path in paths}
    runtime = {str(path): digest(path) for path in index.extension('native-publication-v2').runtime_files()}
    inputs.update(runtime)
    sha = context['source_sha256']
    source = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
    inputs[str(source)] = sha
    for run, expected in context['exports'].items():
        require(re.fullmatch('run-[a-f0-9]+', run) and SHA.fullmatch(expected), 'export pointer')
        inputs[str(root / 'ghidra/request-exports' / sha / run / 'details.json')] = expected
    parent = context['nested_proof']
    parent_path = root / 'knowledge/quest-packet-native-checks-v1' / parent['sha256'] / 'manifest.json'
    require(Path(parent['path']).resolve() == parent_path and digest(parent_path) == parent['sha256'], 'nested parent SHA/path')
    proof = json.loads(parent_path.read_bytes())
    require(proof['source_sha256'] == sha and proof['family'] == 'quest-sync'
            and proof['native_execution'] is True and proof['target_exports_verified'] is True
            and proof['packet_id'] == 1854 and proof['call_counts'] == proof['abi_checks'] == 1076,
            'nested parent scope')
    # Retain actual source/export/tool/runtime dependencies instead of invoking
    # the already-qualified parent matrix for an unchanged common reader.
    retained = proof['inputs']['files']
    require(isinstance(retained, dict) and retained, 'nested retained inputs')
    for name, expected in retained.items():
        require(name not in inputs or inputs[name] == expected, 'nested input conflict')
        inputs[name] = expected
        if Path(name).resolve().is_relative_to(Path(sys.base_prefix).resolve()):
            runtime[name] = expected
    inputs[str(parent_path)] = parent['sha256']
    return context, dict(source_sha256=sha, inputs=inputs, runtime_inputs=runtime,
                         nested_proof=parent)


def validate(report, selected):
    require(report.get('schema') == 1 and report.get('recipe') == RECIPE
            and report.get('definition') == selected and report.get('source_sha256') == selected['source_sha256']
            and report.get('limits') == LIMITS and report.get('manual_start_wire_verified') is True
            and report.get('native_execution') is True
            and all(report.get(key) is False for key in ('runtime_admitted', 'network_used', 'quest_completed')),
            'receipt identity/scope')
    result = report['result']
    expected_requests = [dict(key=str(key), length=length, accepted=length == 8)
                         for key, length in product((0, 110110, 2**64 - 1), range(9))]
    expected_replies = [dict(code=code, key=str(key), length=length, nested_ok=ok,
                            accepted=length == 12 and ok)
                        for code, key, ok, length in product((0, 100, 2**32 - 1),
                            (110110, 2**64 - 1), (False, True), (0, 3, 4, 11, 12))]
    expected_producers = [dict(key=str(key), pending=pending, exists=exists, sent=not pending and exists)
                          for key, pending, exists in product((110110, 2**64 - 1), (False, True), (False, True))]
    expected_eligibility = [dict(state=state, blocked=blocked,
                                accepted=blocked == 'none' and state in (1, 3))
                            for state, blocked in product(range(7),
                                ('none', 'already', 'missing', 'level', 'predecessor', 'condition'))]
    expected_entries = {'0x145828d70': 3, '0x1456fe550': 6, '0x145828d90': 27,
                        '0x1456f03d0': 27, '0x145828de0': 60, '0x14582bd30': 60,
                        '0x145d72d80': 8, '0x145df9910': 42}
    require(result['requests'] == expected_requests and result['outer_replies'] == expected_replies
            and result['producers'] == expected_producers and result['eligibility'] == expected_eligibility
            and result['abi_checks'] == 233 and result['native_entries'] == expected_entries,
            'exact matrix/ABI coverage')


def verify(*, root=ROOT, context_path=CONTEXT):
    index = load('knowledge-index').api()
    root = Path(root).resolve()
    context, selected = definition(index, root, context_path)
    workflow = index.extension('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    barrier(selected['inputs'])
    if cache.is_file():
        pointer = json.loads(cache.read_bytes())
        path = root / 'code-clues' / RECIPE / pointer['sha256'] / 'manifest.json'
        require(Path(pointer['path']).resolve() == path and digest(path) == pointer['sha256'], 'cached artifact')
        validate(json.loads(path.read_bytes()), selected)
        barrier(selected['inputs'])
        return dict(report=str(path), sha256=pointer['sha256'], reused=True)
    result = index.extension('quest-start-cases-v1').run(index, root, context)
    report = dict(schema=1, recipe=RECIPE, source_sha256=selected['source_sha256'], definition=selected,
                  result=result, manual_start_wire_verified=True, native_execution=True, runtime_admitted=False,
                  network_used=False, quest_completed=False, limits=LIMITS)
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
    print(json.dumps(verify(root=args.root)))
