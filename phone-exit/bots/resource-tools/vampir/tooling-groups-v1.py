"""Групповой кэш явных fixture-only проверок; без допуска клиента или runtime."""
import argparse
import ast
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import importlib.machinery
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid


HERE = Path(__file__).resolve().parent
PRODUCER = 'tooling-groups-v1'
ISOLATION = 'isolated-python-v1-temporary-vampir-and-rf-roots'
SHA = re.compile(r'[0-9a-f]{64}')
MODULE = re.compile(r'test_vampir_[A-Za-z0-9_]+')
TOOLS = ('tooling-groups-v1.py', 'tooling-group-worker-v1.py', 'tooling-runtime-v1.py',
         'update-process-group-v4.py')
_ACTIVE = {}
_CANCELLED = set()
_ACTIVE_LOCK = threading.Lock()
_OBJECT_LOCK = threading.Lock()


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + '\n').encode('utf-8')


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(name):
    path = HERE / (name + '.py')
    spec = importlib.util.spec_from_file_location('_tooling_groups_' + name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


def read_json(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(32 * 1024 * 1024 + 1)
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError('Tooling JSON exceeds budget')
    return json.loads(raw.decode('utf-8-sig'))


def runtime_snapshot(workspace):
    return load('tooling-runtime-v1').snapshot(workspace)


def project_path(workspace, name):
    if not isinstance(name, str) or not name or '\\' in name:
        raise ValueError('Dependency needs a canonical project-relative path')
    relative = PurePosixPath(name)
    if relative.is_absolute() or '..' in relative.parts or ':' in name:
        raise ValueError('Dependency escapes workspace')
    unresolved = workspace / Path(*relative.parts)
    for part in (unresolved, *unresolved.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Tooling source is a symlink or reparse point: ' + str(part))
        if part == workspace:
            break
    path = unresolved.resolve()
    if not path.is_relative_to(workspace):
        raise ValueError('Dependency resolves outside workspace')
    if not path.is_file():
        raise ValueError('Tooling dependency missing: ' + name)
    return path


def read_catalog(path):
    tree = ast.parse(Path(path).read_text('utf-8-sig'), filename=str(path))
    nodes = [node for node in tree.body if isinstance(node, ast.Assign)
             and any(isinstance(target, ast.Name) and target.id == 'MODULES' for target in node.targets)]
    if len(nodes) != 1 or len(nodes[0].targets) != 1:
        raise ValueError('Aggregate needs one independent MODULES literal')
    try:
        modules = ast.literal_eval(nodes[0].value)
    except (ValueError, TypeError, SyntaxError):
        raise ValueError('Aggregate MODULES must be literal') from None
    if (not isinstance(modules, (tuple, list)) or not modules
            or any(not isinstance(name, str) or not MODULE.fullmatch(name) for name in modules)
            or len(modules) != len(set(modules))):
        raise ValueError('Aggregate MODULES must contain unique reviewed module names')
    return list(modules)


def aggregate_identity(workspace, definition, expected_modules):
    pattern = definition.get('test_pattern')
    if (not isinstance(pattern, str) or not pattern.startswith('test_vampir_')
            or not pattern.endswith('.py') or any(c in pattern for c in '/\\*?')):
        raise ValueError('Tooling aggregate needs one reviewed test file')
    path = project_path(workspace, 'phone-exit/bots/' + pattern)
    tree = ast.parse(path.read_text('utf-8-sig'), filename=str(path))
    catalogs = [node for node in tree.body if
                isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                    and target.id == 'MODULES' for target in node.targets)]
    if len(catalogs) != 1 or len(catalogs[0].targets) != 1:
        raise ValueError('Aggregate needs one independent MODULES literal')
    try:
        values = ast.literal_eval(catalogs[0].value)
    except (ValueError, TypeError, SyntaxError):
        raise ValueError('Aggregate MODULES must be literal') from None
    if not isinstance(values, (list, tuple)) or list(values) != list(expected_modules):
        raise ValueError('Aggregate MODULES differs from expected modules')
    catalogs[0].value = ast.Constant(value='reviewed-module-catalog-excluded-from-group-keys')
    return path, hashlib.sha256(ast.dump(tree, include_attributes=False).encode('utf-8')).hexdigest()


def validate_manifest(workspace, manifest_path, expected_modules, definition):
    if (definition.get('id') != 'automatic-update-tooling'
            or definition.get('source_scope') != 'tooling'
            or definition.get('offline_reviewed') is not True
            or definition.get('source_sha256') != []
            or definition.get('artifact_dependencies') or definition.get('system_runtime_files')):
        raise ValueError('Only the reviewed fixture-only automatic-update-tooling gate is supported')
    expected_modules = list(expected_modules)
    if (not expected_modules or len(expected_modules) != len(set(expected_modules))
            or any(not isinstance(name, str) or not MODULE.fullmatch(name) for name in expected_modules)):
        raise ValueError('Expected modules must be explicit and unique')
    value = read_json(manifest_path)
    if not isinstance(value, dict) or value.get('schema') != 1:
        raise ValueError('Unsupported tooling group manifest')
    common = value.get('common_dependencies')
    groups = value.get('groups')
    if not isinstance(common, list) or not isinstance(groups, list) or not groups:
        raise ValueError('Missing explicit tooling groups or common dependencies')
    all_modules, group_ids, covered = [], [], set()
    for names in [common] + [group.get('dependencies') if isinstance(group, dict) else None for group in groups]:
        if (not isinstance(names, list) or any(not isinstance(name, str) for name in names)
                or len(names) != len(set(names))):
            raise ValueError('Dependencies must be explicit unique lists')
        for name in names:
            project_path(workspace, name)
        covered.update(names)
    for group in groups:
        if (set(group) - {'id', 'test_modules', 'dependencies', 'timeout_seconds'}
                or not isinstance(group.get('id'), str)
                or not re.fullmatch('[a-z0-9][a-z0-9-]{0,79}', group['id'])):
            raise ValueError('Invalid tooling group definition')
        members = group.get('test_modules')
        timeout = group.get('timeout_seconds', 120)
        if (not isinstance(members, list) or not members
                or any(not isinstance(name, str) or not MODULE.fullmatch(name) for name in members)
                or type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 7200):
            raise ValueError('Invalid tooling group members or timeout')
        if [name for name in expected_modules if name in members] != members:
            raise ValueError('Group must preserve reviewed module order')
        group_ids.append(group['id'])
        all_modules.extend(members)
        for name in members:
            dependency = 'phone-exit/bots/' + name + '.py'
            if dependency not in set(common) | set(group['dependencies']):
                raise ValueError('Test module is absent from dependency coverage: ' + name)
            source = project_path(workspace, dependency)
            spec = importlib.machinery.PathFinder.find_spec(name, [str(workspace / 'phone-exit/bots')])
            if spec is None or spec.origin is None or Path(spec.origin).resolve() != source:
                raise ValueError('Test import origin differs from its pinned source: ' + name)
    if len(group_ids) != len(set(group_ids)) or Counter(all_modules) != Counter(expected_modules):
        raise ValueError('Groups must cover every reviewed module exactly once')
    declared = definition.get('dependencies')
    if (not isinstance(declared, list) or any(not isinstance(name, str) for name in declared)
            or len(declared) != len(set(declared))):
        raise ValueError('Gate dependencies must be unique')
    for name in declared:
        project_path(workspace, name)
    catalog, identity = aggregate_identity(workspace, definition, expected_modules)
    controls = {catalog.relative_to(workspace).as_posix()}
    if manifest_path.is_relative_to(workspace):
        controls.add(manifest_path.relative_to(workspace).as_posix())
    if set(declared) - covered - controls or covered - set(declared):
        raise ValueError('Group dependency coverage differs from the registered gate')
    return value, catalog, identity


def _atomic(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix='tooling-pointer-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _immutable(cache_root, category, filename, raw):
    sha = hashlib.sha256(raw).hexdigest()
    path = cache_root / category / sha / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    # Different groups can produce identical logs. Serialize the short object
    # publication so a second worker cannot inspect a partially written object.
    with _OBJECT_LOCK:
        try:
            with path.open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            if path.read_bytes() != raw:
                raise ValueError('Immutable tooling object collision') from None
    return dict(path=str(path), sha256=sha)


def _object(cache_root, pointer, category, filename):
    if (not isinstance(pointer, dict) or set(pointer) != {'path', 'sha256'}
            or not isinstance(pointer['sha256'], str) or not SHA.fullmatch(pointer['sha256'])):
        raise ValueError('Invalid tooling object pointer')
    expected = cache_root / category / pointer['sha256'] / filename
    path = Path(pointer['path'])
    if path != expected or path.resolve() != expected:
        raise ValueError('Tooling object pointer escapes its namespace')
    if digest(path) != pointer['sha256']:
        raise ValueError('Tooling object SHA changed')
    return path


@contextmanager
def _owner(cache_root):
    cache_root.mkdir(parents=True, exist_ok=True)
    with (cache_root / 'owner.lock').open('a+b') as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b'0')
            stream.flush()
        stream.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ValueError('Another tooling group owner is active') from None
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == 'nt':
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def launch_group(workspace, definition, run_folder, timeout_seconds):
    run_folder = Path(run_folder)
    run_folder.mkdir(parents=True, exist_ok=True)
    request, result, log_path = (run_folder / name for name in ('definition.json', 'result.json', 'worker.log'))
    request.write_bytes(canonical(definition))
    environment = os.environ.copy()
    runtime_tool = load('tooling-runtime-v1')
    effective_path = runtime_tool.worker_path(environment)
    expected_environment = definition['runtime'].get('environment_sha256', {})
    path_sha256 = None if effective_path is None else hashlib.sha256(effective_path.encode('utf-8')).hexdigest()
    if 'PATH' in expected_environment and path_sha256 != expected_environment['PATH']:
        raise ValueError('Tooling worker PATH changed before launch')
    if effective_path is not None:
        environment['PATH'] = effective_path
    environment = {key: value for key, value in environment.items()
                   if not key.upper().startswith('PHONEEXIT_')
                   and key.upper() not in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP')}
    fixture = tempfile.TemporaryDirectory(prefix='fixture-', dir=run_folder)
    command = [sys.executable, '-I', '-B', '-X', 'utf8', '-X',
               'pycache_prefix=' + str(Path(fixture.name) / 'pycache'),
               str(HERE / 'tooling-group-worker-v1.py'),
               '--workspace', str(workspace), '--definition', str(request), '--output', str(result),
               '--fixture-root', fixture.name]
    job, process = None, None
    with fixture, log_path.open('wb') as log:
        try:
            with _ACTIVE_LOCK:
                if run_folder.parent in _CANCELLED:
                    raise ValueError('Tooling invocation was cancelled')
                if os.name == 'nt':
                    job = load('update-process-group-v4').WindowsJob('Local\\PhoneExit.ToolingGroups.' + uuid.uuid4().hex)
                process = subprocess.Popen(command, cwd=workspace, stdin=subprocess.PIPE, stdout=log,
                                           stderr=subprocess.STDOUT, env=environment,
                                           creationflags=0x08000000 if os.name == 'nt' else 0,
                                           start_new_session=os.name != 'nt')
                if job is not None:
                    job.assign(process.pid)
                _ACTIVE[run_folder] = (process, job)
            try:
                process.communicate(b'GO\n', timeout=timeout_seconds)
                state = 'passed' if process.returncode == 0 else 'failed'
            except subprocess.TimeoutExpired:
                state = 'timeout'
            finally:
                if job is not None:
                    job.close()
                    job = None
                elif os.name != 'nt':
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=15)
        finally:
            if job is not None:
                job.close()
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=15)
            with _ACTIVE_LOCK:
                _ACTIVE.pop(run_folder, None)
    return dict(state=state, result_path=str(result) if result.is_file() else None,
                log_path=str(log_path), exit_code=process.returncode)


def _cancel_workers(invocation):
    with _ACTIVE_LOCK:
        _CANCELLED.add(invocation)
        active = [item for folder, item in _ACTIVE.items() if folder.parent == invocation]
    for process, job in active:
        if job is not None:
            job.close()
        elif os.name != 'nt':
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            process.kill()


def validate_worker(value, definition):
    lists = ('test_ids', 'started_ids', 'skipped', 'failures', 'errors', 'expected_failures',
             'unexpected_successes', 'subtest_failures', 'subtest_errors')
    if (not isinstance(value, dict) or value.get('schema') != 1
            or value.get('producer') != 'tooling-group-worker-v1'
            or value.get('group_id') != definition['group']['id']
            or value.get('definition_sha256') != fingerprint(definition)
            or value.get('state') not in ('passed', 'failed')
            or any(not isinstance(value.get(name), list) for name in lists)
            or type(value.get('tests_run')) is not int or value['tests_run'] < 0
            or value['tests_run'] != len(value['started_ids'])):
        raise ValueError('Invalid tooling worker result')
    for name in ('test_ids', 'started_ids', 'unexpected_successes'):
        if any(not isinstance(item, str) or not item for item in value[name]):
            raise ValueError('Invalid tooling test identity')
    if Counter(value['started_ids']) - Counter(value['test_ids']):
        raise ValueError('Worker executed an unlisted test identity')
    remaining_order = iter(value['test_ids'])
    if any(not any(candidate == started for candidate in remaining_order)
           for started in value['started_ids']):
        raise ValueError('Worker reordered discovered test identities')
    for name in ('skipped', 'failures', 'errors', 'expected_failures', 'subtest_failures', 'subtest_errors'):
        for item in value[name]:
            field = 'reason' if name == 'skipped' else 'traceback'
            if (not isinstance(item, dict) or not isinstance(item.get('id'), str)
                    or not isinstance(item.get(field), str)):
                raise ValueError('Invalid worker test outcome')
    failed = any(value[name] for name in ('failures', 'errors', 'unexpected_successes',
                                        'subtest_failures', 'subtest_errors'))
    if (value['state'] == 'passed') == failed:
        raise ValueError('Worker outcome does not match its state')
    if value['state'] == 'passed':
        missing = Counter(value['test_ids']) - Counter(value['started_ids'])
        for skipped in value['skipped']:
            holder = re.fullmatch(r'(?:setUpClass|setUpModule) \(([^()]+)\)', skipped['id'])
            if holder is not None and skipped['reason']:
                prefix = holder[1] + '.'
                missing = Counter({name: count for name, count in missing.items()
                                   if not name.startswith(prefix)})
        if not value['test_ids'] or missing:
            raise ValueError('Successful worker did not account for all discovered tests')
    duration = value.get('duration_seconds')
    if type(duration) not in (int, float) or not math.isfinite(duration) or duration < 0:
        raise ValueError('Invalid worker duration')
    return dict(discovered_cases=len(value['test_ids']), tests_run=value['tests_run'],
                skipped=len(value['skipped']), failures=len(value['failures']), errors=len(value['errors']),
                expected_failures=len(value['expected_failures']),
                unexpected_successes=len(value['unexpected_successes']))


def _save_group(cache_root, definition, launched):
    state = launched.get('state')
    if state not in ('passed', 'failed', 'timeout'):
        raise ValueError('Unknown tooling worker state')
    log = _immutable(cache_root, 'objects', 'worker.log', Path(launched['log_path']).read_bytes())
    result = None
    counts = dict(discovered_cases=0, tests_run=0, skipped=0, failures=0, errors=0,
                  expected_failures=0, unexpected_successes=0)
    if launched.get('result_path') is not None and state != 'timeout':
        path = Path(launched['result_path'])
        value = read_json(path)
        counts = validate_worker(value, definition)
        if value['state'] != state or (state == 'passed' and launched.get('exit_code') != 0):
            raise ValueError('Worker exit state disagrees with result')
        result = _immutable(cache_root, 'objects', 'worker-result.json', path.read_bytes())
    elif state == 'passed':
        raise ValueError('Successful worker did not produce a result')
    report = dict(schema=1, producer=PRODUCER, definition=definition, state=state,
                  worker_result=result, log=log, counts=counts, exit_code=launched.get('exit_code'),
                  proves_client_compatibility=False, runtime_admitted=False)
    pointer = _immutable(cache_root, 'group-results', 'manifest.json', canonical(report))
    return pointer, report


def _load_group(cache_root, pointer, definition):
    path = _object(cache_root, pointer, 'group-results', 'manifest.json')
    report = read_json(path)
    if (report.get('schema') != 1 or report.get('producer') != PRODUCER
            or report.get('definition') != definition or report.get('state') not in ('passed', 'failed', 'timeout')
            or report.get('proves_client_compatibility') is not False or report.get('runtime_admitted') is not False):
        raise ValueError('Cached tooling definition or state changed')
    _object(cache_root, report.get('log'), 'objects', 'worker.log')
    result = report.get('worker_result')
    if result is not None:
        value = read_json(_object(cache_root, result, 'objects', 'worker-result.json'))
        if validate_worker(value, definition) != report.get('counts') or value['state'] != report['state']:
            raise ValueError('Cached tooling counts or worker state changed')
    elif report['state'] == 'passed':
        raise ValueError('Cached success lacks a worker result')
    elif report.get('counts') != dict(discovered_cases=0, tests_run=0, skipped=0, failures=0, errors=0,
                                      expected_failures=0, unexpected_successes=0):
        raise ValueError('Incomplete worker report cannot claim completed test counts')
    if report['state'] == 'passed' and report.get('exit_code') != 0:
        raise ValueError('Cached successful worker has a nonzero exit code')
    return report


def run(workspace, cache_root, manifest_path, expected_modules, check_definition, *, workers=2,
        retry_failed=False):
    if type(workers) is not int or not 1 <= workers <= 2 or type(retry_failed) is not bool:
        raise ValueError('Tooling groups require one or two workers and an explicit retry boolean')
    workspace, cache_root, manifest_path = (Path(path).resolve() for path in
                                           (workspace, cache_root, manifest_path))
    started = time.monotonic()
    with _owner(cache_root):
        manifest, catalog, code_identity = validate_manifest(workspace, manifest_path, expected_modules,
                                                            check_definition)
        all_paths = {project_path(workspace, name) for name in check_definition['dependencies']}
        all_paths |= {catalog, manifest_path} | {HERE / name for name in TOOLS}
        inputs = {str(path): digest(path) for path in sorted(all_paths)}
        runtime = runtime_snapshot(workspace)
        runtime_inputs = dict(runtime.get('files', {}))
        if any(not isinstance(sha, str) or not SHA.fullmatch(sha) for sha in runtime_inputs.values()):
            raise ValueError('Runtime inventory needs full SHA values')
        definitions = []
        policy = {key: value for key, value in check_definition.items()
                  if key not in ('dependencies', 'test_pattern', 'runtime_distributions')}
        tool_inputs = {str(HERE / name): inputs[str(HERE / name)] for name in TOOLS}
        for group in manifest['groups']:
            names = set(manifest['common_dependencies']) | set(group['dependencies'])
            selected = {str(project_path(workspace, name)): inputs[str(project_path(workspace, name))]
                        for name in sorted(names)}
            # Catalog/manifest are full outer inputs; only the selected group and
            # catalog code identity affect this group's reusable result.
            selected.pop(str(catalog), None)
            selected.pop(str(manifest_path), None)
            definitions.append(dict(schema=1, producer=PRODUCER, group=group, inputs=selected,
                                    tools=tool_inputs, runtime=runtime, isolation=ISOLATION,
                                    aggregate_code_sha256=code_identity, gate_policy=policy,
                                    source_scope='tooling', proves_client_compatibility=False))
        invocation = cache_root / 'runs' / uuid.uuid4().hex

        def process(definition):
            key = fingerprint(definition)
            cache = cache_root / 'cache' / (key + '.json')
            if cache.is_file():
                pointer = read_json(cache)
                report = _load_group(cache_root, pointer, definition)
                if report['state'] == 'passed' or not retry_failed:
                    return key, pointer, report, True
            folder = invocation / definition['group']['id']
            launched = launch_group(workspace, definition, folder,
                                    definition['group'].get('timeout_seconds', 120))
            # Completed groups become durable immediately, but only against the
            # complete definition whose inputs are still present now.
            for name, expected in {**definition['inputs'], **definition['tools']}.items():
                if digest(name) != expected:
                    raise ValueError('Tooling group inputs changed during execution')
            if runtime_snapshot(workspace) != runtime:
                raise ValueError('Tooling runtime changed before group receipt publication')
            pointer, report = _save_group(cache_root, definition, launched)
            _atomic(cache, canonical(pointer))
            return key, pointer, report, False

        executor = ThreadPoolExecutor(max_workers=workers)
        try:
            completed = list(executor.map(process, definitions))
        except BaseException:
            executor.shutdown(wait=False, cancel_futures=True)
            _cancel_workers(invocation)
            executor.shutdown(wait=True, cancel_futures=True)
            raise
        else:
            executor.shutdown(wait=True)
        finally:
            with _ACTIVE_LOCK:
                _CANCELLED.discard(invocation)
        # No aggregate proof is published until full inventories are fresh again.
        current, current_catalog, current_code = validate_manifest(workspace, manifest_path, expected_modules,
                                                                  check_definition)
        if (current != manifest or current_catalog != catalog or current_code != code_identity
                or {str(path): digest(path) for path in sorted(all_paths)} != inputs):
            raise ValueError('Tooling inputs changed before aggregate publication')
        if runtime_snapshot(workspace) != runtime:
            raise ValueError('Tooling runtime changed during execution')
        artifacts = dict(runtime_inputs)
        groups, states = [], []
        metrics = dict(executed_groups=0, cached_groups=0, executed_cases=0, cached_cases=0,
                       executed_discovered_cases=0, cached_discovered_cases=0,
                       executed_skips=0, cached_skips=0, incomplete_groups=0)
        for key, pointer, report, reused in completed:
            # Verify every durable object again, including the freshly written ones.
            report = _load_group(cache_root, pointer, report['definition'])
            states.append(report['state'])
            groups.append(dict(id=report['definition']['group']['id'], state=report['state'],
                               report=pointer['path'], sha256=pointer['sha256'], cache_key=key,
                               counts=report['counts']))
            artifacts[pointer['path']] = pointer['sha256']
            for item in (report['worker_result'], report['log']):
                if item is not None:
                    artifacts[item['path']] = item['sha256']
            prefix = 'cached' if reused else 'executed'
            metrics[prefix + '_groups'] += 1
            metrics[prefix + '_cases'] += report['counts']['tests_run']
            metrics[prefix + '_discovered_cases'] += report['counts']['discovered_cases']
            metrics[prefix + '_skips'] += report['counts']['skipped']
            metrics['incomplete_groups'] += report['worker_result'] is None
        state = 'timeout' if 'timeout' in states else 'failed' if 'failed' in states else 'passed'
        aggregate = dict(schema=1, producer=PRODUCER, state=state, groups=groups,
                         inputs=inputs, artifacts=artifacts, runtime_inputs=runtime_inputs,
                         expected_modules=list(expected_modules), check_definition=check_definition,
                         source_scope='tooling', proves_client_compatibility=False, runtime_admitted=False,
                         stable_inputs='Full SHA endpoint comparisons; no atomic filesystem snapshot.')
        pointer = _immutable(cache_root, 'aggregate-results', 'manifest.json', canonical(aggregate))
        metrics['duration_seconds'] = time.monotonic() - started
        return dict(state=state, report=pointer['path'], sha256=pointer['sha256'],
                    cache_key=fingerprint(dict(check=check_definition, inputs=inputs, runtime=runtime,
                                               expected_modules=list(expected_modules))), metrics=metrics)


def grouped_suite(expected_modules):
    class GroupedTooling(unittest.TestCase):
        def runTest(self):
            workspace = HERE.parents[3]
            registry = read_json(HERE / 'knowledge/research-checks.json')
            matches = [item for item in registry['checks'] if item['id'] == 'automatic-update-tooling']
            if len(matches) != 1:
                raise ValueError('Missing unique tooling gate')
            resources = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
            result = run(workspace, resources / 'knowledge/tooling-groups-v1',
                         HERE / 'knowledge/tooling-groups-v1.json', expected_modules, matches[0])
            print(json.dumps(result, ensure_ascii=False), flush=True)
            self.assertEqual(result['state'], 'passed', result['report'])
    return unittest.TestSuite([GroupedTooling()])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=HERE.parents[3])
    parser.add_argument('--cache-root', type=Path)
    parser.add_argument('--manifest', type=Path, default=HERE / 'knowledge/tooling-groups-v1.json')
    parser.add_argument('--registry', type=Path, default=HERE / 'knowledge/research-checks.json')
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--retry-failed', action='store_true')
    args = parser.parse_args(argv)
    checks = [item for item in read_json(args.registry)['checks'] if item['id'] == 'automatic-update-tooling']
    if len(checks) != 1:
        raise ValueError('Missing unique tooling gate')
    path = args.workspace / 'phone-exit/bots' / checks[0]['test_pattern']
    tree = ast.parse(path.read_text('utf-8-sig'))
    catalogs = [node for node in tree.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == 'MODULES' for target in node.targets)]
    if len(catalogs) != 1:
        raise ValueError('Missing independent module catalog')
    modules = ast.literal_eval(catalogs[0].value)
    resources = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
    cache = args.cache_root or resources / 'knowledge/tooling-groups-v1'
    result = run(args.workspace, cache, args.manifest, modules, checks[0],
                 workers=args.workers, retry_failed=args.retry_failed)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result['state'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
