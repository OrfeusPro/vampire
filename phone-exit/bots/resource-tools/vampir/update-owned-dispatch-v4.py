"""Управляемый разовый updater: guardian, изолированная группа и проверенный lock."""
# With -S, no site/startup hooks run before the parent assigns the job. The
# bootstrap consumes only stdin; ordinary imports/site begin after the gate.
import sys

_BOOTSTRAP = None
if __name__ == '__main__' and sys.argv[1:] == ['--worker']:
    _BOOTSTRAP = sys.stdin.buffer.read(262145)
    if not _BOOTSTRAP or len(_BOOTSTRAP) > 262144:
        raise SystemExit('Invalid managed updater handoff')

import codecs
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
RECIPE = 'update-owner-recovery-v4'
MAX_JSON = 32 * 1024 * 1024


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)+'\n').encode('utf-8')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def atomic(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.update-v4-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
        Path(temporary).replace(path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def checked_json(path, limit=MAX_JSON):
    with Path(path).open('rb') as stream:
        raw = stream.read(limit+1)
    if len(raw) > limit:
        raise ValueError('Managed updater JSON exceeds budget')
    return json.loads(raw)


def enabled(index, args):
    path = Path(args.knowledge)/'update-owner-engine.json'
    if not path.is_file():
        return False
    if index.read_json(path) != dict(schema=4, recipe=RECIPE):
        raise ValueError('Неизвестный механизм владельца обновления')
    return True


def guard(knowledge):
    paths = [HERE/name for name in ('update-owned-dispatch-v4.py',
        'update-owner-lease-v4.py', 'update-process-group-v4.py')]
    paths.append(Path(knowledge)/'update-owner-engine.json')
    return {str(path.resolve()): digest(path) for path in paths}


def identity(backend, pid):
    observed = backend.process_probe(pid)
    if observed['state'] != 'alive' or observed.get('creation_time') is None:
        raise ValueError('Не удалось установить точную идентичность процесса обновления')
    return dict(pid=pid, creation_time=observed['creation_time'], session_id=observed['session_id'])


def same_process(observed, expected):
    return (observed.get('state') == 'alive'
        and observed.get('creation_time') == expected['creation_time']
        and observed.get('session_id') == expected['session_id'])


def _options(args, database, operation):
    if operation not in ('auto', 'explicit'):
        raise ValueError('Unknown managed updater operation')
    result = {name: str(Path(getattr(args, name)).resolve()) for name in ('root', 'knowledge', 'install')}
    result.update(database=str(Path(database).resolve()), operation=operation)
    for name in ('baseline', 'resume'):
        value = getattr(args, name, None)
        result[name] = str(Path(value).resolve()) if value is not None else None
    sources = int(result['baseline'] is not None)+int(result['resume'] is not None)
    if sources != (0 if operation == 'auto' else 1):
        raise ValueError('Managed updater source selection differs')
    for name in ('plan_only', 'audit_only'):
        value = getattr(args, name, False)
        if type(value) is not bool:
            raise ValueError('Managed updater flags must be boolean')
        result[name] = value
    workers = getattr(args, 'workers', 2)
    if type(workers) is not int or not 1 <= workers <= 2:
        raise ValueError('Managed updater worker budget differs')
    result['workers'] = workers
    return result


def _args(options):
    keys = {'root', 'knowledge', 'install', 'database', 'operation', 'baseline',
        'resume', 'plan_only', 'audit_only', 'workers'}
    if not isinstance(options, dict) or set(options) != keys:
        raise ValueError('Managed updater options differ')
    for name in ('root', 'knowledge', 'install', 'database'):
        if not isinstance(options[name], str) or not Path(options[name]).is_absolute():
            raise ValueError('Managed updater needs absolute paths')
    args = SimpleNamespace(**options)
    for name in ('root', 'knowledge', 'install', 'database', 'baseline', 'resume'):
        if options[name] is not None:
            setattr(args, name, Path(options[name]))
    args.auto = options['operation'] == 'auto'
    if _options(args, args.database, options['operation']) != options:
        raise ValueError('Managed updater options are not canonical')
    return args


def admitted(index, args, *, backend=None):
    marker = getattr(args, '_update_owner_v4', None)
    if marker is None:
        return False
    if not isinstance(marker, dict) or set(marker) != {'path', 'sha256'}:
        raise ValueError('Invalid managed updater admission')
    path = Path(args.root).resolve()/'knowledge/locks/research.lock'
    if Path(marker['path']) != path or digest(path) != marker['sha256']:
        raise ValueError('Managed updater lock changed')
    record = checked_json(path, 65536)
    backend = backend or load('update-process-group-v4')
    lease_api = load('update-owner-lease-v4')
    record = lease_api.validate_record(record, args.root, guard(args.knowledge))
    if (record.get('schema') != 4 or record.get('recipe') != RECIPE
            or record.get('root') != str(Path(args.root).resolve())
            or record.get('guard') != guard(args.knowledge)
            or record.get('job') != lease_api.job_name(args.root, record.get('epoch', ''))
            or record['worker']['pid'] != os.getpid()
            or record['worker']['session_id'] != backend.current_session_id()
            or not same_process(backend.process_probe(os.getpid()), record['worker'])
            or not same_process(backend.process_probe(record['guardian']['pid']), record['guardian'])
            or not backend.process_in_job(os.getpid(), record['job'],
                creation_time=record['worker']['creation_time'])):
        raise ValueError('Managed updater process/job admission rejected')
    if digest(path) != marker['sha256']:
        raise ValueError('Managed updater lock changed during admission')
    return True


def _group_finished(backend, job, name, timeout=10):
    # Closing our non-inheritable KILL_ON_CLOSE handle contains every assigned
    # descendant even when the direct worker failed. Never terminate by PID.
    job.close()
    deadline = time.monotonic()+timeout
    while True:
        state = backend.probe_job(name)
        if state['state'] == 'missing' or state['active_processes'] == 0:
            return
        if time.monotonic() >= deadline:
            raise ValueError('Группа обновления ещё завершается; lock сохранён')
        time.sleep(0.05)


def _forward(child):
    decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
    while True:
        block = child.stdout.read1(65536)
        if not block:
            break
        text = decoder.decode(block)
        if text:
            sys.stdout.write(text); sys.stdout.flush()
    rest = decoder.decode(b'', final=True)
    if rest:
        sys.stdout.write(rest); sys.stdout.flush()


def dispatch(index, args, database, operation, *, backend=None, launcher=subprocess.Popen):
    if admitted(index, args, backend=backend):
        raise ValueError('Managed worker must invoke its operation directly')
    options = _options(args, database, operation)
    if operation == 'explicit' and not options['resume'] and not (Path(args.knowledge)/'update-contracts.json').is_file():
        raise ValueError('Managed owner requires the resumable update recipe')
    backend = backend or load('update-process-group-v4')
    lease_api = load('update-owner-lease-v4')
    expected_guard = guard(args.knowledge)
    root = Path(args.root).resolve()
    with lease_api.Lease(root) as lease:
        recovered = lease.recover(backend, expected_guard)
        epoch = secrets.token_hex(16)
        folder = root/'knowledge/update-owner-v4/epochs'/epoch
        folder.mkdir(parents=True, exist_ok=False)
        result_path = folder/'result.json'; progress = folder/'progress.json'
        name = lease_api.job_name(root, epoch)
        guardian = identity(backend, os.getpid())
        job = backend.WindowsJob(name)
        child = None; record = None; claimed = False; drained = False; assigned = False
        pump = None; output_errors = []
        try:
            child = launcher([sys.executable, '-S', '-X', 'utf8', str(HERE/'update-owned-dispatch-v4.py'), '--worker'],
                cwd=str(HERE.parents[3]), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                close_fds=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            worker = identity(backend, child.pid)
            job.assign(child.pid, creation_time=worker['creation_time'])
            assigned = True
            if guard(args.knowledge) != expected_guard:
                raise ValueError('Managed updater tools changed during startup')
            record = dict(schema=4, recipe=RECIPE, epoch=epoch, root=str(root),
                guardian=guardian, worker=worker, job=name, guard=expected_guard, operation=operation)
            pointer = lease.claim(record)
            if pointer is None:
                pointer = dict(path=str(root/'knowledge/locks/research.lock'),
                    sha256=digest(root/'knowledge/locks/research.lock'))
            claimed = True
            if checked_json(folder/'owner.json', 65536) != record:
                raise ValueError('Managed updater owner snapshot differs')
            atomic(progress, dict(state='starting', epoch=epoch, run=None))
            atomic(root/'knowledge/update-owner-v4/current.json', dict(schema=4, epoch=epoch,
                owner=record, lock=pointer, progress=str(progress), result=str(result_path), recovered=recovered))
            payload = canonical(dict(options=options, lock=pointer))
            if len(payload) > 262144:
                raise ValueError('Managed updater handoff exceeds budget')
            child.stdin.write(payload); child.stdin.close()
            print(json.dumps(dict(event='update_owner_v4', state='running', epoch=epoch, worker_pid=child.pid)), flush=True)
            def forward():
                try:
                    _forward(child)
                except BaseException as error:
                    output_errors.append(error)
            pump = threading.Thread(target=forward, name='update-owner-output', daemon=True)
            pump.start()
            while True:
                if output_errors:
                    raise ValueError('Managed updater output failed') from output_errors[0]
                try:
                    returncode = child.wait(timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    pass
            _group_finished(backend, job, name); drained = True
            pump.join(timeout=10)
            if pump.is_alive() or output_errors:
                raise ValueError('Managed updater output did not finish')
            if not result_path.is_file():
                raise ValueError('Managed updater stopped without result; returncode='+str(returncode))
            envelope = checked_json(result_path)
            if set(envelope) != {'epoch', 'state', 'result'} or envelope['epoch'] != epoch:
                raise ValueError('Managed updater result identity differs')
            if returncode != 0 or envelope['state'] != 'completed':
                raise ValueError('Managed updater failed: '+str(envelope['result']))
            result = envelope['result']
            if not isinstance(result, dict):
                raise ValueError('Managed updater returned an invalid result')
            atomic(progress, dict(state='completed', epoch=epoch, run=result.get('run'),
                result_sha256=digest(result_path)))
            return result
        finally:
            try:
                if child is not None and not assigned:
                    # Popen retains the exact newly created process handle;
                    # it is safe to clean up this still-gated, unassigned child.
                    child.kill()
                if not drained:
                    _group_finished(backend, job, name); drained = True
                if child is not None:
                    child.wait(timeout=10)
                if pump is not None:
                    pump.join(timeout=10)
                    if pump.is_alive():
                        raise ValueError('Managed updater output thread is still active')
                if claimed and drained:
                    lease.release(record)
            finally:
                job.close()
                if child is not None:
                    for stream in (child.stdin, child.stdout):
                        if stream is not None and not stream.closed:
                            stream.close()


def worker(raw):
    payload = json.loads(raw)
    if not isinstance(payload, dict) or set(payload) != {'options', 'lock'}:
        raise ValueError('Invalid managed updater payload')
    args = _args(payload['options']); args._update_owner_v4 = payload['lock']
    # Only stdlib/backend probes execute until both the immutable lock and OS
    # membership have been checked. Site hooks inherit the already assigned job.
    if not admitted(None, args):
        raise ValueError('Managed updater admission missing')
    record = checked_json(payload['lock']['path'], 65536)
    folder = args.root/'knowledge/update-owner-v4/epochs'/record['epoch']
    try:
        import site
        site.main()
        index = load('knowledge-index').api()
        def created(path, current):
            if not admitted(index, args):
                raise ValueError('Managed updater admission lost')
            path = Path(path).resolve()
            if not path.is_relative_to(args.root/'knowledge/update-runs') or path.name != 'run.json':
                raise ValueError('Managed journal outside update runs')
            atomic(folder/'progress.json', dict(state='running', epoch=record['epoch'],
                run=str(path), source_sha256=current['source_sha256']))
        args.journal_created = created
        result = (index.extension('update-auto').execute(index, args, args.database)
            if args.operation == 'auto' else index.extension('research-update').update(index, args, args.database))
        atomic(folder/'result.json', dict(epoch=record['epoch'], state='completed', result=result))
        return 0
    except BaseException as error:
        atomic(folder/'result.json', dict(epoch=record['epoch'], state='failed',
            result=dict(error_type=type(error).__name__, reason=str(error)[:2048])))
        raise


def lock_status(root, *, backend=None):
    """Read-only diagnostics; uncertainty never authorizes recovery."""
    path = Path(root).resolve()/'knowledge/locks/research.lock'
    try:
        record = checked_json(path, 65536)
        if record.get('schema') != 4 or record.get('recipe') != RECIPE or record['root'] != str(Path(root).resolve()):
            raise ValueError('Unknown managed updater lock')
        backend = backend or load('update-process-group-v4')
        guardian = backend.process_probe(record['guardian']['pid'])
        worker_state = backend.process_probe(record['worker']['pid'])
        return dict(scheme=RECIPE, epoch=record['epoch'], pid=record['guardian']['pid'],
            alive=same_process(guardian, record['guardian']), worker_pid=record['worker']['pid'],
            worker_alive=same_process(worker_state, record['worker']),
            action='Read-only status; recovery requires the managed lease and an empty job')
    except (OSError, ValueError, KeyError, TypeError) as error:
        return dict(scheme=RECIPE, alive=None, reason=str(error), action='Inspect managed owner; status never removes locks')


if __name__ == '__main__':
    if _BOOTSTRAP is None:
        raise SystemExit('Only the guardian may start this worker')
    raise SystemExit(worker(_BOOTSTRAP))
