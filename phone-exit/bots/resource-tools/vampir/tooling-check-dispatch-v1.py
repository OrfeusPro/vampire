"""Route the reviewed tooling gate through resumable groups; keep client checks frozen."""
import hashlib
import importlib.util
from pathlib import Path


HERE = Path(__file__).resolve().parent
CHECK_ID = 'automatic-update-tooling'
MANIFEST = 'tooling-groups-v1.json'


def load_engine():
    path = HERE / 'tooling-groups-v1.py'
    spec = importlib.util.spec_from_file_location('dispatched_tooling_groups_v1', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def selected_checks(workflow, index, knowledge, question, check_ids):
    checks = workflow.registry(index, knowledge)['checks']
    if check_ids is not None and (not isinstance(check_ids, list) or not check_ids
            or any(not isinstance(name, str) for name in check_ids)
            or len(check_ids) != len(set(check_ids))
            or any(sum(row['id'] == name for row in checks) != 1 for name in check_ids)):
        raise ValueError('Explicit checks must name unique registered IDs')
    return [row for row in checks if (row['id'] in check_ids if check_ids is not None
                                     else question in row['questions'])]


def inputs(index, workspace, knowledge, definition):
    paths = {index.child(workspace, name) for name in definition['dependencies']}
    paths |= {workspace / 'phone-exit/bots' / definition['test_pattern'],
              Path(knowledge) / MANIFEST, Path(knowledge) / 'research-checks.json',
              Path(__file__).resolve()}
    return {str(path.resolve()): digest(path) for path in sorted(paths)}


def merge(target, additional):
    for name, sha in additional.items():
        if name in target and target[name] != sha:
            raise ValueError('Tooling group input changed: ' + name)
        target[name] = sha


def grouped(index, workflow, args, definition):
    if workflow.source_scope(definition) != 'tooling' or definition['id'] != CHECK_ID:
        raise ValueError('Grouped execution only supports the reviewed tooling gate')
    workspace = index.HERE.parents[3]
    manifest = Path(args.knowledge) / MANIFEST
    before = inputs(index, workspace, args.knowledge, definition)
    engine = load_engine()
    catalog = engine.read_catalog(workspace / 'phone-exit/bots/test_vampir_update_automation.py')
    outcome = engine.run(workspace, Path(args.root) / 'knowledge/tooling-groups-v1',
                         manifest, catalog, definition, workers=2)
    pointer = dict(path=outcome['report'], sha256=outcome['sha256'])
    if digest(pointer['path']) != pointer['sha256']:
        raise ValueError('Tooling aggregate receipt changed')
    receipt = index.read_json(pointer['path'])
    if (receipt.get('source_scope') != 'tooling'
            or receipt.get('proves_client_compatibility') is not False
            or receipt.get('state') != outcome['state']):
        raise ValueError('Tooling aggregate changed scope or state')
    checked_inputs = dict(before)
    merge(checked_inputs, receipt['inputs'])
    artifacts = dict(receipt['artifacts'])
    runtime_inputs = dict(receipt.get('runtime_inputs', {}))
    if any(artifacts.get(name) != sha for name, sha in runtime_inputs.items()):
        raise ValueError('Tooling runtime inputs do not match the checked artifacts')
    merge(artifacts, {pointer['path']: pointer['sha256']})
    if inputs(index, workspace, args.knowledge, definition) != before:
        raise ValueError('Tooling gate inputs changed during grouped execution')
    for name, expected in {**checked_inputs, **artifacts}.items():
        if digest(name) != expected:
            raise ValueError('Tooling gate final SHA barrier failed: ' + name)
    report_definition = dict(check=definition, source_sha256=None, source_scope='tooling',
        proves_client_compatibility=False, inputs=checked_inputs, artifacts=artifacts,
        runtime_inputs=runtime_inputs,
        group_aggregate=pointer, runner_sha256=before[str(Path(__file__).resolve())])
    # Invocation durations/cache hits remain in the group runner's journal. The
    # admitted report is deterministic, so an unchanged scoped check reuses it.
    report = dict(schema=1, definition=report_definition, state=outcome['state'],
                  grouped_tooling=True, aggregate=pointer,
                  proves_client_compatibility=False, runtime_admitted=False)
    path = workflow.snapshot(args.root, 'tooling-check-results-v1', report)
    key = hashlib.sha256(workflow.canonical(report_definition)).hexdigest()
    return dict(id=CHECK_ID, state=outcome['state'], report=str(path), sha256=digest(path),
                cache_key=key, source_scope='tooling', proves_client_compatibility=False)


def run_checks(index, args, sha, question, *, check_ids=None, workflow=None):
    workflow = workflow or index.extension('research-workflow')
    if not (Path(args.knowledge) / MANIFEST).is_file():
        return workflow.run_checks(index, args, sha, question, check_ids=check_ids)
    outcomes = []
    for definition in selected_checks(workflow, index, args.knowledge, question, check_ids):
        if definition['id'] == CHECK_ID:
            outcomes.append(grouped(index, workflow, args, definition))
        elif sha in definition.get('generated_sdk_contexts', {}):
            outcomes.extend(index.extension('sdk-check-guard').run(index, workflow, args, sha, definition))
        elif sha in definition.get('version_flow_contexts', {}):
            outcomes.extend(index.extension('version-result-flow-guard').run(index, workflow, args, sha, definition))
        elif sha in definition.get('sdk_launcher_profiles', {}):
            outcomes.extend(index.extension('sdk-launcher-check-guard').run(index, workflow, args, sha, definition))
        elif sha in definition.get('sdk_fetch_contexts', {}):
            outcomes.extend(index.extension('sdk-fetch-check-guard').run(index, workflow, args, sha, definition))
        elif sha in definition.get('candidate_bridge_profiles', {}):
            outcomes.extend(index.extension('candidate-bridge-check-guard').run(index, workflow, args, sha, definition))
        else:
            outcomes.extend(workflow.run_checks(index, args, sha, question,
                                               check_ids=[definition['id']]))
    return outcomes
