"""Управляемый research lock; чужие и прежние PID-only locks не очищаются.

На Windows удаление выполняется через проверенный file handle. POSIX ветка
предназначена для fixtures с cooperating writers под этой же OS lease.
"""
import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import threading

RECIPE = 'update-owner-recovery-v4'
LIMIT = 64 * 1024
SHA = re.compile(r'[0-9a-f]{64}')
EPOCH = re.compile(r'[0-9a-f]{32}')
FIELDS = {'schema', 'recipe', 'epoch', 'root', 'guardian', 'worker', 'job', 'guard', 'operation'}


class LeaseError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__('Блокировка обновления: ' + reason)


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
        allow_nan=False) + '\n').encode('utf-8')


def fingerprint(record):
    return hashlib.sha256(canonical(record)).hexdigest()


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise LeaseError('duplicate_managed_json_key')
        value[key] = item
    return value


def _bounded(path):
    with Path(path).open('rb') as stream: raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise LeaseError('managed_document_size_budget')
    return raw


def job_name(root, epoch):
    if not isinstance(epoch, str) or not EPOCH.fullmatch(epoch):
        raise LeaseError('invalid_epoch')
    digest = hashlib.sha256(str(Path(root).resolve()).casefold().encode('utf-8')).hexdigest()[:20]
    return 'Local\\PhoneExit-Vampir-Update-v4-' + digest + '-' + epoch


def _identity(value):
    if (not isinstance(value, dict) or set(value) != {'pid', 'creation_time', 'session_id'}
            or type(value['pid']) is not int or not 0 < value['pid'] <= 0xffffffff
            or not isinstance(value['creation_time'], str)
            or not re.fullmatch(r'[1-9][0-9]{0,19}', value['creation_time'])
            or int(value['creation_time']) > 0xffffffffffffffff
            or type(value['session_id']) is not int or not 0 <= value['session_id'] <= 0xffffffff):
        raise LeaseError('invalid_process_identity')


def _guard(value):
    if (not isinstance(value, dict) or not 1 <= len(value) <= 64
            or any(not isinstance(path, str) or len(path) > 4096 or not Path(path).is_absolute()
                or not isinstance(sha, str) or not SHA.fullmatch(sha) for path, sha in value.items())):
        raise LeaseError('invalid_producer_guard')


def validate_record(record, root, expected_guard=None):
    root = Path(root).resolve()
    if (not isinstance(record, dict) or set(record) != FIELDS
            or type(record['schema']) is not int or record['schema'] != 4
            or record['recipe'] != RECIPE or record['root'] != str(root)
            or record['operation'] not in ('auto', 'explicit')):
        raise LeaseError('invalid_managed_lock_schema')
    if not isinstance(record['epoch'], str) or not EPOCH.fullmatch(record['epoch']):
        raise LeaseError('invalid_epoch')
    _identity(record['guardian']); _identity(record['worker']); _guard(record['guard'])
    if record['guardian']['pid'] == record['worker']['pid']:
        raise LeaseError('guardian_and_worker_must_differ')
    if record['guardian']['session_id'] != record['worker']['session_id']:
        raise LeaseError('guardian_worker_session_mismatch')
    if record['job'] != job_name(root, record['epoch']):
        raise LeaseError('foreign_job_name')
    if expected_guard is not None:
        _guard(expected_guard)
        if record['guard'] != expected_guard:
            raise LeaseError('managed_guard_changed')
    return copy.deepcopy(record)


def _file_id(stat):
    if not stat.st_ino:
        raise LeaseError('file_identity_unavailable')
    return (stat.st_dev, stat.st_ino)


def _kernel():
    from ctypes import wintypes
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    api.CreateFileW.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]; api.CloseHandle.restype = wintypes.BOOL
    api.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
        ctypes.c_void_p, wintypes.DWORD]
    api.SetFileInformationByHandle.restype = wintypes.BOOL
    return api


class _PinnedFile:
    """READ pin blocks Win32 write/delete. DELETE pin removes this exact object."""
    def __init__(self, path, *, delete=False):
        self.path, self.delete, self.stream = Path(path), delete, None
        if os.name == 'nt':
            import msvcrt
            api = _kernel()
            # OPEN_REPARSE_POINT never follows a last-component replacement.
            handle = api.CreateFileW(str(self.path), 0x80000000 | (0x10000 if delete else 0),
                1, None, 3, 0x00200000 | 0x80, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                fd = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
            except BaseException:
                api.CloseHandle(handle)
                raise
        else:
            fd = os.open(self.path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            self.stream = os.fdopen(fd, 'rb')
            self.identity = _file_id(os.fstat(self.stream.fileno()))
        except BaseException:
            if self.stream is not None: self.stream.close()
            else: os.close(fd)
            raise

    def read(self):
        self.stream.seek(0)
        raw = self.stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise LeaseError('managed_lock_size_budget')
        return raw

    def close(self):
        if self.stream is not None:
            self.stream.close(); self.stream = None

    def remove(self):
        if not self.delete:
            raise LeaseError('delete_handle_required')
        if os.name == 'nt':
            import msvcrt
            flag = ctypes.c_ubyte(1)
            if not _kernel().SetFileInformationByHandle(msvcrt.get_osfhandle(self.stream.fileno()),
                    4, ctypes.byref(flag), ctypes.sizeof(flag)):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            # Fixture implementation: all managed writers hold the OS lease.
            if _file_id(self.path.stat()) != self.identity:
                raise LeaseError('managed_lock_identity_changed')
            self.path.unlink()


class Lease:
    def __init__(self, root):
        self.input_root = Path(root).absolute()
        self.root = self.input_root.resolve()
        self.folder = self.root/'knowledge/update-owner-v4'
        self.path = self.root/'knowledge/locks/research.lock'
        self.research_lock = self.path
        self._stream = self._pin = None
        self._owner = self._owned_raw = self._owned_id = self._owner_snapshot = None

    def _paths(self, *paths):
        if self.input_root.resolve() != self.root:
            raise LeaseError('resource_root_alias_changed')
        for path in (self.folder, self.path, *paths):
            path = Path(path)
            if not path.is_relative_to(self.root) or path.resolve() != path:
                raise LeaseError('managed_path_alias_changed')

    def _held(self):
        if self._stream is None or self._owner != (os.getpid(), threading.get_ident()):
            raise LeaseError('lease_not_held_by_current_owner')
        self._paths()
        if _file_id(os.fstat(self._stream.fileno())) != _file_id(self.lease_path.stat()):
            raise LeaseError('lease_file_identity_changed')

    def __enter__(self):
        if self._stream is not None:
            raise LeaseError('lease_already_entered')
        self._paths()
        self.folder.mkdir(parents=True, exist_ok=True)
        self.lease_path = self.folder/'owner.lease'
        self._paths(self.lease_path)
        stream = self.lease_path.open('a+b', buffering=0)
        try:
            if os.fstat(stream.fileno()).st_size == 0: stream.write(b'0')
            stream.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            stream.close()
            raise LeaseError('managed_update_owner_busy') from None
        self._stream, self._owner = stream, (os.getpid(), threading.get_ident())
        try: self._held()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *unused):
        # Leaving without release intentionally retains the managed lock for
        # the next explicit owner; only the OS lease and READ pin are closed.
        if self._stream is not None and self._owner != (os.getpid(), threading.get_ident()):
            raise LeaseError('lease_not_held_by_current_owner')
        if self._pin is not None: self._pin.close(); self._pin = None
        stream, self._stream = self._stream, None
        self._owner = None
        if stream is not None:
            try:
                stream.seek(0)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            finally: stream.close()

    def _put(self, path, raw, *, same=False):
        self._held(); path = Path(path); self._paths(path, path.parent)
        if len(raw) > LIMIT: raise LeaseError('managed_document_size_budget')
        path.parent.mkdir(parents=True, exist_ok=True)
        self._paths(path, path.parent)
        fd, name = tempfile.mkstemp(prefix='.owner-v4-', dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            self._held(); self._paths(temporary, path)
            try: os.link(temporary, path)
            except FileExistsError:
                if not same or _bounded(path) != raw:
                    raise LeaseError('managed_document_already_exists') from None
            self._paths(path)
            if _bounded(path) != raw:
                raise LeaseError('managed_document_changed_during_publication')
        finally:
            self._paths(temporary)
            temporary.unlink(missing_ok=True)
        return dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest())

    def claim(self, record):
        self._held()
        if self._owned_raw is not None: raise LeaseError('lease_already_claimed')
        value = validate_record(record, self.root)
        if value['guardian']['pid'] != os.getpid():
            raise LeaseError('guardian_is_not_current_owner')
        raw = canonical(value)
        snapshot = self.folder/'epochs'/value['epoch']/'owner.json'
        self._owner_snapshot = self._put(snapshot, raw, same=True)
        pointer = self._put(self.path, raw)
        self._pin = _PinnedFile(self.path)
        self._owned_raw, self._owned_id = raw, self._pin.identity
        self._same(self._pin, raw, self._owned_id)
        return pointer

    def _same(self, pin, raw, identity, *, path=None):
        self._held()
        path = self.path if path is None else Path(path)
        self._paths(path)
        if pin.identity != identity or pin.read() != raw or _file_id(path.stat()) != identity:
            raise LeaseError('managed_lock_identity_or_bytes_changed')

    def _remove(self, pin, raw, identity):
        self._same(pin, raw, identity)
        pin.close()
        # Re-open with DELETE access. A substitution in the tiny reopen gap
        # is detected by file identity and full bytes before any deletion.
        removing = _PinnedFile(self.path, delete=True)
        try:
            self._same(removing, raw, identity)
            removing.remove()
        finally: removing.close()
        self._held()

    def release(self, record):
        self._held()
        if self._pin is None or self._owned_raw is None or canonical(record) != self._owned_raw:
            raise LeaseError('foreign_managed_lock_release')
        self._paths(self._owner_snapshot['path'])
        if hashlib.sha256(_bounded(self._owner_snapshot['path'])).hexdigest() != self._owner_snapshot['sha256']:
            raise LeaseError('owner_snapshot_changed')
        self._remove(self._pin, self._owned_raw, self._owned_id)
        self._pin = None
        self._owned_raw = self._owned_id = self._owner_snapshot = None

    def recover(self, backend, expected_guard):
        self._held(); _guard(expected_guard)
        if self._owned_raw is not None: raise LeaseError('cannot_recover_own_active_claim')
        try: self.path.lstat()
        except FileNotFoundError: return None
        self._paths()
        pin = _PinnedFile(self.path)
        owner_pin = None
        try:
            raw, identity = pin.read(), pin.identity
            if raw.strip().isdigit(): raise LeaseError('legacy_pid_lock_requires_manual_inspection')
            try: record = json.loads(raw, object_pairs_hook=_unique_pairs)
            except LeaseError: raise
            except (ValueError, UnicodeError): raise LeaseError('invalid_managed_lock_json') from None
            record = validate_record(record, self.root, expected_guard)
            if canonical(record) != raw:
                raise LeaseError('noncanonical_managed_lock')
            owner_path = self.folder/'epochs'/record['epoch']/'owner.json'
            self._paths(owner_path)
            try: owner_pin = _PinnedFile(owner_path)
            except FileNotFoundError:
                raise LeaseError('managed_owner_snapshot_missing') from None
            except OSError as error:
                if getattr(error, 'winerror', None) in (2, 3):
                    raise LeaseError('managed_owner_snapshot_missing') from None
                raise
            if owner_pin.read() != raw:
                raise LeaseError('managed_owner_snapshot_changed')
            self._same(owner_pin, raw, owner_pin.identity, path=owner_path)
            session = backend.current_session_id()
            if type(session) is not int or session != record['guardian']['session_id']:
                raise LeaseError('managed_session_changed_or_unknown')
            observations = {}
            for role in ('guardian', 'worker'):
                observed = backend.process_probe(record[role]['pid'])
                if not isinstance(observed, dict) or observed.get('state') not in ('alive', 'exited'):
                    raise LeaseError('managed_process_state_unknown')
                if observed['state'] == 'alive':
                    _identity(dict(pid=record[role]['pid'], creation_time=observed.get('creation_time'), session_id=observed.get('session_id')))
                    if observed['creation_time'] == record[role]['creation_time']:
                        raise LeaseError('managed_' + role + '_still_alive')
                elif observed.get('creation_time') is not None or observed.get('session_id') is not None:
                    raise LeaseError('inconsistent_exited_process_identity')
                observations[role] = copy.deepcopy(observed)
            group = backend.probe_job(record['job'])
            if (not isinstance(group, dict) or group.get('state') not in ('missing', 'present')
                    or type(group.get('active_processes')) is not int or group['active_processes'] < 0
                    or (group['state'] == 'missing' and group['active_processes'] != 0)):
                raise LeaseError('managed_job_state_unknown')
            if group['active_processes']:
                raise LeaseError('managed_descendants_still_alive')
            self._same(pin, raw, identity)
            epoch = self.folder/'epochs'/record['epoch']
            archive = self._put(epoch/'recovered-research.lock', raw, same=True)
            receipt = dict(schema=4, recipe=RECIPE, epoch=record['epoch'], root=str(self.root),
                lock_sha256=hashlib.sha256(raw).hexdigest(), lock_file_identity=list(identity),
                owner_snapshot=dict(path=str(owner_path), sha256=hashlib.sha256(raw).hexdigest()),
                owner_file_identity=list(owner_pin.identity),
                archived_lock=archive, process_observations=observations, job_observation=copy.deepcopy(group),
                guard=copy.deepcopy(expected_guard), session_id=session,
                validation_scope='windows_file_handle_recovery' if os.name == 'nt' else 'cooperative_posix_fixture_recovery')
            attempt = epoch/'recovery-attempts'/fingerprint(receipt)
            prepared = self._put(attempt/'prepared.json', canonical(dict(receipt, state='prepared')), same=True)
            self._same(pin, raw, identity)
            self._same(owner_pin, raw, owner_pin.identity, path=owner_path)
            self._remove(pin, raw, identity)
            self._same(owner_pin, raw, owner_pin.identity, path=owner_path)
            return self._put(attempt/'completed.json', canonical(dict(receipt,
                state='recovered', prepared=prepared)), same=True)
        finally:
            pin.close()
            if owner_pin is not None: owner_pin.close()
