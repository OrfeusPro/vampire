"""Preparation, bounded collection and explicit result recording; no game IO."""
from contextlib import contextmanager
import hashlib
import importlib.metadata
import json
import locale
import os
import platform
import re
from pathlib import Path
import subprocess
import sys
import tempfile


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')


def atomic(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix='research-')
    try:
        with os.fdopen(descriptor, 'wb') as stream: stream.write(raw)
        Path(name).replace(path)
    finally:
        if Path(name).exists(): Path(name).unlink()


def snapshot(root, category, value):
    raw = canonical(value)
    sha = hashlib.sha256(raw).hexdigest()
    path = root / 'knowledge' / category / sha / 'manifest.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('xb') as stream: stream.write(raw)
    except FileExistsError:
        if path.read_bytes() != raw: raise ValueError('Immutable research manifest collision')
    return path


@contextmanager
def locked(root, name):
    path = root / 'knowledge/locks' / (name + '.lock')
    path.parent.mkdir(parents=True, exist_ok=True)
    try: descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise ValueError('Research operation locked: ' + str(path) + '; inspect recorded PID before removing a stale lock') from None
    try:
        os.write(descriptor, str(os.getpid()).encode('ascii'))
        yield
    finally:
        os.close(descriptor)
        path.unlink()


def checked_manifest(index, path):
    path = path.resolve()
    if index.digest(path) != path.parent.name: raise ValueError('Research manifest digest mismatch')
    return index.read_json(path)


def registry(index, knowledge):
    path = knowledge / 'research-checks.json'
    return index.read_json(path) if path.is_file() else dict(schema=1, checks=[])


# Explicitly reviewed fixture-only infrastructure suites. New entries require
# code review; a native check cannot obtain version independence by a JSON flag.
TOOLING_CHECKS = {
    'update-contract-registry': 'test_vampir_update_contracts.py',
    'update-binding-closure': 'test_vampir_function_reuse.py',
    'update-run-offline': 'test_vampir_update_run.py',
    'tooling-check-scope': 'test_vampir_tooling_check_scope.py',
    'knowledge-index-incremental': 'test_vampir_knowledge_index.py',
    'check-source-variants': 'test_vampir_check_source_variants.py',
    'automatic-update-tooling': 'test_vampir_update_automation.py',
}


def source_scope(check):
    scope = check.get('source_scope', 'client')
    if scope not in ('client', 'tooling'):
        raise ValueError('Unknown offline check source scope')
    variants=check.get('source_variants',{})
    if not isinstance(variants,dict) or (variants and scope!='client'):
        raise ValueError('Source variants require client scope')
    for sha,variant in variants.items():
        if (not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha)
                or sha not in check.get('source_sha256',[]) or not isinstance(variant,dict)
                or not variant or set(variant)-{'test_pattern','dependencies','artifact_dependencies','timeout_seconds'}):
            raise ValueError('Invalid reviewed source variant')
    if scope == 'tooling' and (TOOLING_CHECKS.get(check['id']) != check.get('test_pattern')
            or check.get('offline_reviewed') is not True or check.get('source_sha256') != []
            or check.get('artifact_dependencies') or check.get('system_runtime_files')):
        raise ValueError('Tooling scope requires a reviewed fixture-only infrastructure suite')
    return scope


def source_definition(check,sha):
    """An explicit SHA may select its reviewed suite; it cannot alter permissions."""
    source_scope(check)
    variant=check.get('source_variants',{}).get(sha)
    if variant is None:return check
    effective={key:value for key,value in check.items() if key!='source_variants'}
    effective.update(variant)
    effective['selected_source_variant']=sha
    return effective


def system_runtime_files(names):
    """Resolve only explicitly supported Windows CRT input, never arbitrary paths."""
    if not isinstance(names, list) or len(names) > 1 or any(n != 'ucrtbase.dll' for n in names):
        raise ValueError('Unsupported system runtime dependency')
    if not names: return []
    if sys.platform != 'win32': raise ValueError('Windows CRT check requires Windows')
    import ctypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    kernel.GetSystemDirectoryW.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    size = kernel.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < size < len(buffer): raise ValueError('Cannot resolve Windows system directory')
    return [(Path(buffer.value)/name).resolve() for name in names]


def check_artifacts(index, root, names):
    """Hash public exports and immutable release resources, including their PAK."""
    external = {}
    for name in names:
        path = index.child(root, name)
        if path.is_relative_to((root / 'ghidra').resolve()):
            external[str(path)] = index.digest(path)
            continue
        parts = path.relative_to(root.resolve()).parts
        if (len(parts) == 3 and parts[0] == 'client-code-snapshots'
                and index.SHA.fullmatch(parts[1]) and parts[2] == 'ProjectRED-Win64-Shipping.exe'):
            actual = index.digest(path)
            if actual != parts[1]:
                raise ValueError('Check client snapshot hash changed')
            external[str(path)] = actual
            continue
        if (len(parts) == 4 and parts[0] == 'knowledge'
                and parts[1] in ('login-result-discovery-11320', 'login-batch-alignment-11320')
                and index.SHA.fullmatch(parts[2]) and parts[3] == 'manifest.json'):
            data = checked_manifest(index, path)
            if not index.SHA.fullmatch(data.get('source_sha256', '')):
                raise ValueError('Check public research source missing')
            external[str(path)] = index.digest(path)
            continue
        if (len(parts) == 3 and parts[0] == 'resource-config-snapshots'
                and index.SHA.fullmatch(parts[1]) and path.name == 'manifest.json'):
            data = checked_manifest(index, path)
            if data.get('authoritative_directory_for_archive') is not True or data.get('configs') != []:
                raise ValueError('Check needs a directory-only recovery manifest')
            release_sha = data.get('release_manifest_sha256', '')
            if not index.SHA.fullmatch(release_sha): raise ValueError('Invalid directory release SHA')
            release = checked_manifest(index, root / 'release-snapshots' / release_sha / 'manifest.json')
            source = Path(data['source_archive']['path']).resolve()
            expected = data.get('archive_sha256', '')
            if (source.suffix.lower() != '.pak' or not index.SHA.fullmatch(expected)
                    or not any(Path(row['path']).resolve() == source
                        and row.get('current', {}).get('sha256') == expected for row in release['files'])
                    or index.digest(source) != expected):
                raise ValueError('Check directory source archive changed or is not release-bound')
            external[str(source)] = expected
            for filename, field in [('directory.json', 'directory_paths_file_sha256'),
                                    ('encoded-entries.bin', 'encoded_entries_file_sha256')]:
                material = index.child(path.parent, filename)
                if index.digest(material) != data.get(field):
                    raise ValueError('Check directory material hash changed')
                external[str(material)] = index.digest(material)
            external[str(path)] = index.digest(path)
            external[str(root / 'release-snapshots' / release_sha / 'manifest.json')] = release_sha
            continue
        if len(parts) < 3 or parts[0] != 'release-snapshots' or not index.SHA.fullmatch(parts[1]):
            raise ValueError('Check artifact must be public Ghidra or release evidence')
        if path.name == 'manifest.json':
            data = checked_manifest(index, path)
            # The root release manifest uses "source" as a descriptive string.
            source = data.get('source') if len(parts) > 3 else None
            if source is not None:
                if not isinstance(source, dict) or not isinstance(source.get('path'), str):
                    raise ValueError('Invalid check release source descriptor')
                release = checked_manifest(index, root / 'release-snapshots' / parts[1] / 'manifest.json')
                source_path = Path(source['path']).resolve()
                expected = source.get('sha256', '')
                if (source_path.suffix.lower() != '.pak' or not index.SHA.fullmatch(expected)
                        or not any(Path(row['path']).resolve() == source_path
                            and row.get('current', {}).get('sha256') == expected for row in release['files'])):
                    raise ValueError('Check source must be a full-hash release PAK')
                actual = index.digest(source_path)
                if actual != expected:
                    raise ValueError('Check source archive changed; refresh release snapshot')
                external[str(source_path)] = actual
        elif path.parent.name == 'csv-blobs' and path.suffix == '.csv' and index.SHA.fullmatch(path.stem):
            if index.digest(path) != path.stem:
                raise ValueError('Check CSV content hash changed')
        else:
            raise ValueError('Check release artifact must be a manifest or CSV blob')
        external[str(path)] = index.digest(path)
    return external


def run_checks(index, args, sha, question, *, check_ids=None):
    results = []
    workspace = index.HERE.parents[3]
    checks = registry(index, args.knowledge)['checks']
    if check_ids is not None and (not isinstance(check_ids, list) or not check_ids
            or any(not isinstance(name, str) for name in check_ids)
            or len(check_ids) != len(set(check_ids))
            or any(sum(c['id'] == name for c in checks) != 1 for name in check_ids)):
        raise ValueError('Explicit checks must name unique registered IDs')
    for check in checks:
        if check_ids is not None:
            if check['id'] not in check_ids: continue
        elif question not in check['questions']: continue
        scope = source_scope(check)
        if scope == 'client' and sha not in check['source_sha256']:
            results.append(dict(id=check['id'], state='requires_port', reason='No reviewed check for this source SHA'))
            continue
        check=source_definition(check,sha)
        # Registry holds reviewed offline unittest targets, never shell commands.
        pattern = check['test_pattern']
        if not pattern.startswith('test_vampir_') or not pattern.endswith('.py') or any(c in pattern for c in '/\\*?'):
            raise ValueError('Check needs one explicit offline unittest file')
        test_path = workspace / 'phone-exit/bots' / pattern
        dependencies = [test_path]
        for name in check['dependencies']:
            dependencies.append(index.child(workspace, name))
        dependencies = sorted(set(dependencies))
        inputs = {str(p): index.digest(p) for p in dependencies}
        external = check_artifacts(index, args.root, check.get('artifact_dependencies', []))
        for path in system_runtime_files(check.get('system_runtime_files', [])):
            external[str(path)] = index.digest(path)
        definition = dict(check=check, source_sha256=None if scope == 'tooling' else sha, inputs=inputs, artifacts=external,
            python_version=platform.python_version(), executable=sys.executable,
            runner_sha256=index.digest(Path(__file__)))
        if scope == 'tooling':
            definition.update(source_scope='tooling', proves_client_compatibility=False)
        if check.get('system_runtime_files'):
            definition['system_runtime_locale'] = locale.setlocale(locale.LC_ALL)
        definition['runtime_metadata'] = {}
        for name in check.get('runtime_distributions', []):
            matches = list(importlib.metadata.distributions(path=[str(index.HERE.parents[2] / '.tools/vampir-analysis')]))
            selected = [d for d in matches if d.metadata['Name'].lower() == name.lower()]
            if len(selected) != 1: raise ValueError('Missing or ambiguous offline check runtime: ' + name)
            definition['runtime_metadata'][name] = dict(version=selected[0].version,
                record_sha256=hashlib.sha256((selected[0].read_text('RECORD') or '').encode()).hexdigest())
        key = hashlib.sha256(canonical(definition)).hexdigest()
        cache = args.root / 'knowledge/check-cache' / (key + '.json')
        if cache.is_file():
            pointer = index.read_json(cache)
            report_path = Path(pointer['report'])
            report = checked_manifest(index, report_path)
            if report.get('definition') != definition: raise ValueError('Check cache input mismatch')
        else:
            if check.get('offline_reviewed') is not True: raise ValueError('Check is not reviewed for offline execution')
            command = [sys.executable, '-X', 'utf8', '-m', 'unittest', 'discover', '-s',
                'phone-exit/bots', '-p', pattern, '-v']
            with tempfile.TemporaryFile() as log:
                try:
                    completed = subprocess.run(command, cwd=workspace, stdout=log,
                        stderr=subprocess.STDOUT, timeout=check.get('timeout_seconds', 120))
                    state = 'passed' if completed.returncode == 0 else 'failed'
                except subprocess.TimeoutExpired:
                    state = 'timeout'
                if ({str(p): index.digest(p) for p in dependencies} != inputs
                        or any(index.digest(name) != sha for name,sha in external.items())):
                    raise ValueError('Check inputs changed during execution')
                if check.get('system_runtime_files') and locale.setlocale(locale.LC_ALL) != definition['system_runtime_locale']:
                    raise ValueError('Check runtime locale changed during execution')
                log.seek(0)
                output = log.read(1024 * 1024 + 1)
            report = dict(schema=1, definition=definition, state=state,
                output=output[:1024*1024].decode('utf-8', errors='replace'), truncated=len(output)>1024*1024)
            report_path = snapshot(args.root, 'check-results', report)
            atomic(cache, canonical(dict(report=str(report_path))))
        outcome = dict(id=check['id'], state=report['state'], report=str(report_path),
            sha256=index.digest(report_path), cache_key=key)
        if scope == 'tooling':
            outcome.update(source_scope='tooling', proves_client_compatibility=False)
        results.append(outcome)
    return results


def function_state(index, db, sha, at):
    rows = index.query(db, 'function', at, sha, 200)
    usable = [r for r in rows if r['completed'] and r['pseudocode'] and db.execute(
        'SELECT body_json FROM variants WHERE id=?', (r['variant'],)).fetchone()]
    usable = [r for r in usable if json.loads(db.execute(
        'SELECT body_json FROM variants WHERE id=?', (r['variant'],)).fetchone()[0]).get('instructions')]
    return dict(address=at, state='ready' if usable else 'incomplete' if rows else 'missing', variants=rows)


def prepare(index, args, database):
    with locked(args.root, 'research'):
        index.build(args.root, database, knowledge=args.knowledge)
        db = index.open_index(database)
        try:
            sha = index.select_release(db, args.release)
            if sha is None: raise ValueError('Research needs exactly one source SHA, not all')
            questions = index.read_json(args.knowledge / 'questions.json')['questions']
            matches = [q for q in questions if q['id'] == args.question]
            if len(matches) != 1: raise ValueError('Unknown or ambiguous question ID')
            question = matches[0]
            addresses = sorted({index.address(a) for a in args.function}, key=lambda a:int(a,16))
            if not 1 <= len(addresses) <= 32: raise ValueError('Research address budget is 1..32')
            functions = [function_state(index, db, sha, at) for at in addresses]
            related = set()
            for term in (args.question, *addresses):
                related.update(row['variant'] for row in index.query(db,'search',term,sha,200))
            context = [dict(r) for r in db.execute('SELECT * FROM context WHERE source_sha IN (?,?)', (sha,''))
                if (r['id'] in related or args.question in r['payload'] or any(at.lower() in r['payload'].lower() for at in addresses)
                    or r['path'] in {str((args.knowledge / p).resolve()) for p in question['evidence']})]
            for row in context: row['payload'] = json.loads(row['payload'])
            source = db.execute('SELECT source FROM releases WHERE sha=?', (sha,)).fetchone()[0]
            pinned = {source: sha}
            for f in functions:
                for variant in f['variants']:
                    for key in ('artifact', 'pseudocode'):
                        if variant[key]: pinned[variant[key]] = index.digest(variant[key])
            request = dict(schema=1, source_sha256=sha, source=source,
                require_installed_match=args.release == 'installed', question=args.question,
                question_snapshot=question, question_applicability='historical_context_not_release_proof',
                question_sha256=index.digest(args.knowledge / 'questions.json'),
                reason=args.reason or question['next_action'], functions=functions, context=context,
                inputs=pinned, context_inputs={r['path']:index.digest(r['path']) for r in context},
                checks=run_checks(index, args, sha, args.question),
                limits=['Explicit addresses only; no role transfer or game/network actions.'])
        finally: db.close()
        path = snapshot(args.root, 'requests', request)
        return dict(request=str(path), sha256=index.digest(path), source_sha256=sha,
            functions=[dict(address=f['address'], state=f['state']) for f in functions], checks=request['checks'])


def load_request(index, args):
    request = checked_manifest(index, args.request)
    if request.get('schema') != 1 or not index.SHA.fullmatch(request['source_sha256']):
        raise ValueError('Unsupported research request')
    if request['require_installed_match'] and index.digest(index.INSTALL) != request['source_sha256']:
        raise ValueError('Installed client changed; prepare a new request')
    for name, expected in request['inputs'].items():
        if index.digest(name) != expected: raise ValueError('Research input changed: ' + name)
    return request


def collector(index, args, request, addresses):
    candidates = []
    for path in (args.root / 'ghidra/release-comparisons').glob('*/run-*/provenance.json'):
        receipt = index.read_json(path)
        if receipt.get('new_source_sha256') == request['source_sha256']:
            if index.digest(path.parent / 'candidates.json') != receipt['files']['candidates.json']:
                raise ValueError('Comparison candidate hash mismatch')
            candidates.append(path.parent)
    if len(candidates) > 1:
        return dict(state='queued', reason='Missing or ambiguous Ghidra comparison project', addresses=addresses)
    if not candidates:
        return index.extension('collect-requested-functions').collect(index, args, request, addresses)
    # Validate requested starts on real unwind boundaries. No guessed data address
    # is passed to createFunction. Leaf/tail candidates need a separate reviewed export.
    native = index.extension('build-native-entry-code')
    image = native.Image(Path(request['source']).read_bytes())
    permitted, queued = [], []
    for at in addresses:
        location = image.containing(int(at,16))
        if location is not None and image.roots[location][0] + image.pe.base == int(at,16): permitted.append(at)
        else: queued.append(dict(address=at, reason='Not an unambiguous unwind root; needs reviewed boundary evidence'))
    if not permitted: return dict(state='queued', queue=queued)
    audit = index.extension('audit-client-release')
    references = dict(schema=1, source_sha256=request['source_sha256'],
        references=[dict(function=at, reason='Explicit request and source unwind root; no role claim') for at in permitted])
    target = audit.save_snapshot(candidates[0] / 'sdk-reference-candidates', references)
    command = [sys.executable, '-X', 'utf8', str(index.HERE / 'inspect-release-function-candidates.py'),
        str(candidates[0]), '--sdk-profile', '--sdk-reference-candidates', str(target),
        '--sdk-functions', ','.join(permitted)]
    with locked(args.root, 'ghidra'):
        # The pinned runner owns the child JVM and waits for it. Do not kill only
        # the parent on timeout and leave an orphan holding the project lock.
        completed = subprocess.run(command, stdout=sys.stderr)
    if completed.returncode: raise ValueError('Ghidra collection failed; inspect preserved export logs')
    return dict(state='collected', addresses=permitted, queue=queued)


def collect(index, args, database):
    with locked(args.root, 'research'):
        request = load_request(index, args)
        index.build(args.root, database, knowledge=args.knowledge)
        db = index.open_index(database)
        try:
            states = [function_state(index, db, request['source_sha256'], f['address']) for f in request['functions']]
        finally: db.close()
        missing = [f['address'] for f in states if f['state'] != 'ready']
        key = index.digest(args.request)
        attempted = args.root / 'knowledge/collection-attempts' / (key + '.json')
        if not missing: outcome = dict(state='reused', addresses=[])
        elif attempted.exists():
            outcome = dict(state='queued', reason='This request was already attempted; inspect outcome or prepare changed inputs',
                previous=index.read_json(attempted), addresses=missing)
        else:
            atomic(attempted, canonical(dict(state='started', addresses=missing)))
            try:
                outcome = collector(index, args, request, missing)
                index.build(args.root, database, knowledge=args.knowledge)
                db = index.open_index(database)
                try:
                    remaining = [function_state(index,db,request['source_sha256'],at) for at in missing]
                finally: db.close()
                if outcome['state'] == 'collected':
                    incomplete = [dict(address=f['address'],reason='Export remains '+f['state'])
                        for f in remaining if f['state'] != 'ready']
                    if incomplete:
                        outcome['state'] = 'partial'
                        outcome.setdefault('queue',[]).extend(incomplete)
                atomic(attempted, canonical(outcome))
            except BaseException:
                atomic(attempted, canonical(dict(state='failed', addresses=missing)))
                raise
        receipt = snapshot(args.root, 'collections', dict(request_sha256=key, outcome=outcome))
        return dict(report=str(receipt), **outcome)


def finish(index, args, database):
    with locked(args.root, 'research'):
        request = load_request(index, args)
        result = index.read_json(args.result)
        required = ('question', 'source_sha256', 'addresses', 'conclusion', 'method', 'limits', 'unknown', 'next_check', 'evidence')
        missing = [field for field in required if not result.get(field)]
        if missing: raise ValueError('Incomplete research result; missing: ' + ', '.join(missing))
        if result['question'] != request['question'] or result['source_sha256'] != request['source_sha256']:
            raise ValueError('Result does not belong to this request/source')
        result['addresses'] = sorted({index.address(a) for a in result['addresses']})
        if result['method'] not in ('static', 'bounded_native'):
            raise ValueError('Supported result methods: static, bounded_native')
        if not set(result['addresses']) <= {f['address'] for f in request['functions']}:
            raise ValueError('Result introduces an address outside explicit research request')
        allowed = (args.knowledge.resolve(), (args.root / 'ghidra').resolve())
        for evidence in result['evidence']:
            path = Path(evidence['path']).resolve()
            if not any(path.is_relative_to(folder) for folder in allowed):
                raise ValueError('Evidence must be a knowledge document or public Ghidra research artifact')
            evidence['path'] = str(path)
        checks = run_checks(index, args, request['source_sha256'], request['question'])
        if any(c['state'] != 'passed' for c in checks): raise ValueError('Required checks are not passed: ' + json.dumps(checks))
        client_checks = [c for c in checks if c.get('source_scope', 'client') == 'client']
        if result['method'] == 'bounded_native' and not client_checks:
            raise ValueError('Native claim needs a source-bound client check')
        fact = {field:result[field] for field in required}
        # Tooling tests can gate the workflow, but cannot prove client semantics.
        fact['checks'] = client_checks
        fact['id'] = hashlib.sha256(canonical(fact)).hexdigest()
        index.extension('knowledge-context').validate_fact(index, fact, request['source_sha256'], {request['question']})
        target = args.knowledge / 'releases' / request['source_sha256'] / 'facts.json'
        previous = target.read_bytes() if target.exists() else None
        facts = json.loads(previous) if previous else dict(schema=1, source_sha256=request['source_sha256'], facts=[])
        if not any(f['id'] == fact['id'] for f in facts['facts']): facts['facts'].append(fact)
        atomic(target, canonical(facts))
        try:
            consistency(index, args.knowledge)
            index.build(args.root, database, knowledge=args.knowledge)
        except BaseException:
            if previous is None: target.unlink()
            else: atomic(target, previous)
            raise
        receipt = snapshot(args.root, 'completions', dict(request_sha256=index.digest(args.request),
            result_sha256=index.digest(args.result), fact_id=fact['id'], facts=str(target), checks=checks))
        return dict(state='recorded', fact_id=fact['id'], facts=str(target), report=str(receipt), checks=checks)


def consistency(index, knowledge):
    for definition in registry(index, knowledge)['checks']:
        source_scope(definition)
    questions = index.read_json(knowledge / 'questions.json')['questions']
    ids = [q['id'] for q in questions]
    if len(ids) != len(set(ids)): raise ValueError('Duplicate question IDs')
    for question in questions:
        for name in question.get('evidence', []):
            if not index.child(knowledge, name).is_file(): raise ValueError('Question evidence missing: ' + name)
    for path in (knowledge / 'releases').glob('*/facts.json'):
        data = index.read_json(path)
        for fact in data['facts']:
            index.extension('knowledge-context').validate_fact(index, fact, path.parent.name, set(ids))
    if knowledge == index.KNOWLEDGE:
        result = index.extension('check-knowledge').check()
        if result['broken']: raise ValueError('Broken knowledge links: ' + json.dumps(result['broken']))


def check(index, args, database):
    consistency(index, args.knowledge)
    # Only changed Markdown receives style checks; historic technical prose is
    # never silently reformatted. No code or identifiers are rewritten.
    workspace = index.HERE.parents[3]
    names = subprocess.run(['git', 'diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'],
        cwd=workspace, capture_output=True, check=True).stdout.decode('utf-8').split('\0')
    failures = []
    for name in names:
        if not name.endswith('.md'): continue
        staged = subprocess.run(['git', 'show', ':' + name], cwd=workspace,
            capture_output=True, check=True).stdout.decode('utf-8-sig')
        fenced = False
        for number, line in enumerate(staged.splitlines(), 1):
            if line.lstrip().startswith(('```', '~~~')): fenced = not fenced
            if fenced: continue
            if re.match(r'^\\#{1,6}\s', line):
                failures.append(dict(path=name, line=number, reason='Escaped Markdown heading'))
            if line.rstrip().endswith('\\') and re.search(r'\\[()]', line):
                failures.append(dict(path=name, line=number, reason='Possibly escaped Markdown pasted as literal text'))
    if failures: raise ValueError('Review Markdown manually: ' + json.dumps(failures,ensure_ascii=False))
    index.build(args.root, database, knowledge=args.knowledge)
    return dict(state='passed', knowledge_consistent=True, staged_markdown_checked=len([p for p in names if p.endswith('.md')]),
        limits='Structural checks do not establish semantic truth or replace review of Russian text and numeric meaning.')
