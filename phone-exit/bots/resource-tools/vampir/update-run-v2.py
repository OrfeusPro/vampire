"""Выбранные exports для штатного обновления; discovery SQLite не даёт допуск."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import os

HERE = Path(__file__).resolve().parent
RECIPE = 'scoped-native-update-v2'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def enabled(index, args):
    path = Path(args.knowledge) / 'update-engine.json'
    if not path.is_file():
        return False
    value = index.read_json(path)
    if value != dict(schema=2, recipe=RECIPE, native_drivers='native-drivers-v2',
                     research='research-scoped-v2', full_history_audit='knowledge-index.py check'):
        raise ValueError('Неизвестный recipe обновления')
    return True


def tools(index):
    return {str(HERE / name): index.digest(HERE / name) for name in (
        'update-run-v2.py', 'knowledge-scope-v2.py', 'knowledge-index.py',
        'research-workflow.py', 'update-bindings.py', 'extract-native-enums.py')}


def ensure_index(index, args, database):
    """Create a distinct selected DB; never assert global discovery integrity."""
    if (not hasattr(args, '_scope_v2_state')
            or args._scope_v2_state['source_store'] is not args.source_store):
        folder = Path(args.root) / 'knowledge/scoped-native-databases-v2'
        folder.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix='selected-', suffix='.sqlite3', dir=folder)
        os.close(descriptor)
        path = Path(name)
        connection = sqlite3.connect(path)
        try:
            index.schema(connection)
            connection.commit()
        finally:
            connection.close()
        args.scoped_database = path
        args._scope_v2_state = dict(discovery=Path(database).resolve(), scopes=[],
            source_store=args.source_store, hints={}, admitted={}, databases={str(path): index.digest(path)},
            definition_tools=tools(index))
    return dict(database=str(args.scoped_database), reused=False,
        writer_started=True, validation_scope='selected_materials_only',
        global_history_verified=False, discovery_database=str(args._scope_v2_state['discovery']))


def _export_hint(index, path):
    path = Path(path).resolve()
    receipt = index.receipt_for(path)
    if not receipt.is_file():
        return None
    return dict(report=dict(path=str(path), sha256=index.digest(path)),
                receipt=dict(path=str(receipt), sha256=index.digest(receipt)))


def _sidecar_hints(index, args, sha):
    folder = Path(args.root) / 'knowledge/scoped-export-pointers-v2' / sha
    paths = sorted(folder.glob('*.json'))
    if len(paths) > 4096:
        raise ValueError('Слишком много scoped export pointers')
    result = []
    for path in paths:
        value = index.read_json(path)
        if (set(value) != {'source_sha256', 'export_hints'} or value['source_sha256'] != sha
                or not isinstance(value['export_hints'], list)):
            raise ValueError('Неверный scoped export pointer')
        result.extend(value['export_hints'])
    return result


def _write_rows(index, args, scope, functions):
    state = args._scope_v2_state
    path = Path(args.scoped_database)
    if index.digest(path) != state['databases'][str(path)]:
        raise ValueError('Selected SQLite изменился вне своего владельца')
    connection = sqlite3.connect(path)
    try:
        with connection:
            for function in functions:
                key = (scope.source_sha256, function['address'])
                previous = state['admitted'].get(key)
                variants = {row['variant'] for row in function['variants']}
                if previous and previous != variants:
                    raise ValueError('Проверенные варианты адреса изменились внутри прохода')
                state['admitted'][key] = variants
                connection.execute('INSERT OR IGNORE INTO releases VALUES(?,?)',
                    (scope.source_sha256, str(scope.source_path)))
                for row in function['variants']:
                    receipt = row['receipt']
                    connection.execute('INSERT OR IGNORE INTO artifacts VALUES(?,?,?,?,?,?)', (
                        row['artifact'], row['artifact_sha256'], receipt['path'], receipt['sha256'],
                        'verified_selected_source_and_outputs', json.dumps(dict(recipe=RECIPE))))
                    connection.execute('INSERT OR IGNORE INTO functions VALUES(?,?)', key)
                    connection.execute('INSERT OR IGNORE INTO variants VALUES(?,?,?,?,?,?,?)', (
                        row['variant'], row['source_sha'], row['address'], row['pseudocode_sha256'],
                        int(row['completed']), row['message'], row['body_json']))
                    connection.execute('INSERT OR IGNORE INTO observations VALUES(?,?,?,?,?,?,?)', (
                        row['artifact'], row['source_sha'], row['address'], row['variant'],
                        row['names'], row['pseudocode'], row['ordinal']))
        if connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Selected SQLite повреждён')
    finally:
        connection.close()
    state['databases'][str(path)] = index.digest(path)


def _select(index, args, sha, addresses, extra_hints=()):
    state = args._scope_v2_state
    scope = index.extension('knowledge-scope-v2').Scope.open(args.root, args.knowledge,
        sha, addresses, tools(index), source_store=args.source_store)
    all_hints = [*state['hints'].get(sha, []), *_sidecar_hints(index, args, sha), *extra_hints]
    hints = scope.discover_candidates(state['discovery'], all_hints)
    functions = scope.select(hints)
    _write_rows(index, args, scope, functions)
    retained = state['hints'].setdefault(sha, [])
    retained.extend(hint for hint in hints if hint not in retained)
    return scope, functions, hints


def collect_batches(index, workflow, journal, args, database, contexts, sha):
    ensure_index(index, args, database)
    engine = index.extension('update-run')
    addresses = sorted({at for value in contexts['contracts'].values()
        for at in value['bindings'].values()}, key=lambda at: int(at, 16))
    equivalent = engine.function_equivalences(contexts, sha)
    results = []
    # Retain the exact v1 function-only receipt: it never grants semantic
    # admission and contains ordered, source-bound resolver evidence.
    for at, proofs in equivalent.items():
        identities = {sha} | {row['proof']['baseline_sha256'] for row in proofs}
        for identity in identities:
            args.source_store.source(identity)
        binding_stage = getattr(journal, 'run', {}).get('stages', {}).get('bindings', {})
        receipt = dict(schema=1, source_sha256=sha, address=at, bindings=proofs,
            tools={name:index.digest(HERE / name) for name in (
                'update-bindings.py', 'build-native-entry-code.py', 'extract-native-enums.py')},
            binding_stage_key=binding_stage.get('key'),
            resolver_inputs_sha256=engine.fingerprint(workflow, binding_stage['inputs']) if binding_stage.get('inputs') else None,
            resolver_tools=binding_stage.get('inputs', {}).get('tools'),
            source_identities=sorted(identities), scope='function_only', runtime_activated=False,
            semantic_checks_bypassed=False,
            limits=['Declared instruction/callee/data closure only; source semantic checks remain required.'])
        path = workflow.snapshot(args.root, 'function-equivalence-results', receipt)
        results.append(dict(address=at, state='equivalent', artifacts=[], report=str(path), sha256=index.digest(path)))
    pending = [at for at in addresses if at not in equivalent]
    for offset in range(0, len(pending), 32):
        batch = pending[offset:offset + 32]
        scope, functions, hints = _select(index, args, sha, batch)
        missing = [row['address'] for row in functions if row['state'] != 'ready']
        if missing:
            request = dict(schema=1, source_sha256=sha, source=str(scope.source_path),
                require_installed_match=False, functions=[dict(address=at) for at in missing],
                inputs={str(scope.source_path):sha},
                reason='Explicit scoped native update batch; no automatic call-tree expansion')
            request_path = workflow.snapshot(args.root, 'update-export-requests', request)
            from types import SimpleNamespace
            subargs = SimpleNamespace(**vars(args)); subargs.request = request_path
            projects = {str(path):index.digest(path) for path in
                (Path(args.root) / 'ghidra/request-projects' / sha).glob('project.json')}
            projects.update({str(path):index.digest(path) for path in
                (Path(args.root) / 'ghidra/release-comparisons').glob('*/run-*/provenance.json')})
            before = {str(path) for path in index.discover(args.root)}
            outcome = journal.stage('exports-' + engine.fingerprint(workflow, missing)[:16],
                dict(request=index.digest(request_path), source=sha, projects=projects,
                    tools={name:index.digest(HERE / name) for name in (
                        'collect-requested-functions.py', 'InspectVampirSdkProfile.java', 'ghidra-tools.lock.json')}),
                lambda:workflow.collector(index, subargs, request, missing))
            results.append(outcome)
            new_paths = [Path(outcome['export'])] if outcome.get('export') else [
                path for path in index.discover(args.root) if str(path) not in before]
            extra = [hint for path in new_paths if (hint := _export_hint(index, path)) is not None]
            scope, functions, hints = _select(index, args, sha, batch, extra)
            if outcome.get('state') == 'collected':
                folder = Path(args.root) / 'knowledge/scoped-export-pointers-v2' / sha
                body = dict(source_sha256=sha, export_hints=extra)
                workflow.atomic(folder / (hashlib.sha256(workflow.canonical(body)).hexdigest() + '.json'),
                    workflow.canonical(body))
        # Keep the admission closure, not a second copy of report/runtime
        # buffers per family. The final barrier rereads these exact bytes.
        args._scope_v2_state['scopes'].append(scope.finish_barrier())
        for row in functions:
            results.append(dict(address=row['address'], state=row['state'], artifacts=[
                dict(path=variant['artifact'], sha256=variant['artifact_sha256'])
                for variant in row['variants'] if variant['completed']]))
    return results


def finish(index, args):
    state = getattr(args, '_scope_v2_state', None)
    if state is None:
        return dict(validation_scope='selected_materials_only', global_history_verified=False, scopes=0)
    if tools(index) != state['definition_tools']:
        raise ValueError('Scoped update tools изменились')
    if any(index.digest(path) != expected for path, expected in state['databases'].items()):
        raise ValueError('Selected SQLite изменился после admission')
    receipts = state['scopes']
    inputs = {}
    for row in receipts:
        for path, expected in row['inputs'].items():
            if path in inputs and inputs[path] != expected:
                raise ValueError('Scoped input изменился между семействами')
            inputs[path] = expected
    if any(index.digest(path) != expected for path, expected in inputs.items()):
        raise ValueError('Scoped input изменился перед окончательной публикацией')
    args.source_store.validate()
    return dict(validation_scope='selected_materials_only', global_history_verified=False,
        scopes=len(receipts), selected_rows=len(state['admitted']),
        global_historical_pseudocode_reads=0,
        selected_pseudocode_reads=sum(row['metrics']['selected_pseudocode_reads'] for row in receipts),
        inputs=inputs)
