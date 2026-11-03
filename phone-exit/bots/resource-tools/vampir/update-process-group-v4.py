"""Windows Job Object для принадлежащих обновлятору процессов; без политики locks.

Группа создаётся до передачи задания worker. Потомки должны оставаться в группе;
последний handle закрывается только владельцем. Этот модуль не запускает процессы,
не удаляет locks и не трактует отказ доступа как отсутствие процесса или группы.
"""
import ctypes
import os
import re

DWORD = ctypes.c_uint32
BOOL = ctypes.c_int32
HANDLE = ctypes.c_void_p
SIZE_T = ctypes.c_size_t
ULONGLONG = ctypes.c_uint64
LONGLONG = ctypes.c_int64

JOB_OBJECT_QUERY = 0x0004
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000
HANDLE_FLAG_INHERIT = 0x00000001
PROCESS_TERMINATE = 0x0001
PROCESS_SET_QUOTA = 0x0100
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
WAIT_FAILED = 0xFFFFFFFF
ERROR_FILE_NOT_FOUND = 2
ERROR_INVALID_PARAMETER = 87
ERROR_ALREADY_EXISTS = 183


class FILETIME(ctypes.Structure):
    _fields_ = [('dwLowDateTime', DWORD), ('dwHighDateTime', DWORD)]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [('PerProcessUserTimeLimit', LONGLONG), ('PerJobUserTimeLimit', LONGLONG),
        ('LimitFlags', DWORD), ('MinimumWorkingSetSize', SIZE_T),
        ('MaximumWorkingSetSize', SIZE_T), ('ActiveProcessLimit', DWORD),
        ('Affinity', SIZE_T), ('PriorityClass', DWORD), ('SchedulingClass', DWORD)]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ULONGLONG) for name in ('ReadOperationCount', 'WriteOperationCount',
        'OtherOperationCount', 'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [('BasicLimitInformation', JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ('IoInfo', IO_COUNTERS), ('ProcessMemoryLimit', SIZE_T), ('JobMemoryLimit', SIZE_T),
        ('PeakProcessMemoryUsed', SIZE_T), ('PeakJobMemoryUsed', SIZE_T)]


class JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
    _fields_ = [(name, LONGLONG) for name in ('TotalUserTime', 'TotalKernelTime',
        'ThisPeriodTotalUserTime', 'ThisPeriodTotalKernelTime')] + [
        (name, DWORD) for name in ('TotalPageFaultCount', 'TotalProcesses',
        'ActiveProcesses', 'TotalTerminatedProcesses')]


def _api():
    if os.name != 'nt':
        raise OSError('Группы процессов обновлятора требуют Windows')
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    signatures = {
        'CreateJobObjectW': ([ctypes.c_void_p, ctypes.c_wchar_p], HANDLE),
        'OpenJobObjectW': ([DWORD, BOOL, ctypes.c_wchar_p], HANDLE),
        'SetInformationJobObject': ([HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD], BOOL),
        'QueryInformationJobObject': ([HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD,
            ctypes.POINTER(DWORD)], BOOL),
        'SetHandleInformation': ([HANDLE, DWORD, DWORD], BOOL),
        'GetHandleInformation': ([HANDLE, ctypes.POINTER(DWORD)], BOOL),
        'AssignProcessToJobObject': ([HANDLE, HANDLE], BOOL),
        'IsProcessInJob': ([HANDLE, HANDLE, ctypes.POINTER(BOOL)], BOOL),
        'OpenProcess': ([DWORD, BOOL, DWORD], HANDLE),
        'GetProcessTimes': ([HANDLE, *([ctypes.POINTER(FILETIME)] * 4)], BOOL),
        'ProcessIdToSessionId': ([DWORD, ctypes.POINTER(DWORD)], BOOL),
        'WaitForSingleObject': ([HANDLE, DWORD], DWORD),
        'CloseHandle': ([HANDLE], BOOL),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(api, name)
        function.argtypes, function.restype = arguments, result
    return api


def _error(operation, code=None):
    code = ctypes.get_last_error() if code is None else code
    error = ctypes.WinError(code) if os.name == 'nt' else OSError(code, operation)
    error.add_note(operation)
    return error


def _name(name):
    if (not isinstance(name, str) or not re.fullmatch(r'Local\\[A-Za-z0-9_.-]{1,200}', name)):
        raise ValueError('Нужно явное имя Job Object в локальной Windows session')
    return name


def _pid(pid):
    if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF:
        raise ValueError('Нужен положительный Windows PID')
    return pid


def _creation(value):
    if value is not None and (not isinstance(value, str) or not value.isdecimal()
            or not 0 < int(value) <= 0xFFFFFFFFFFFFFFFF or str(int(value)) != value):
        raise ValueError('Нужно точное FILETIME создания процесса')
    return value


def _close(api, handle):
    if not api.CloseHandle(handle):
        raise _error('CloseHandle')


def _active(api, handle):
    information = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
    returned = DWORD()
    if not api.QueryInformationJobObject(handle, 1, ctypes.byref(information),
            ctypes.sizeof(information), ctypes.byref(returned)):
        raise _error('QueryInformationJobObject(accounting)')
    if returned.value != ctypes.sizeof(information):
        raise ValueError('Windows вернул неполную информацию о группе процессов')
    return int(information.ActiveProcesses)


def _wait(api, handle):
    state = api.WaitForSingleObject(handle, 0)
    if state not in (WAIT_OBJECT_0, WAIT_TIMEOUT):
        raise _error('WaitForSingleObject(process)',
            None if state == WAIT_FAILED else ERROR_INVALID_PARAMETER)
    return state


def _identity(api, handle, pid):
    values = [FILETIME() for _ in range(4)]
    if not api.GetProcessTimes(handle, *[ctypes.byref(value) for value in values]):
        raise _error('GetProcessTimes')
    creation = str((values[0].dwHighDateTime << 32) | values[0].dwLowDateTime)
    if _wait(api, handle) == WAIT_OBJECT_0:
        return dict(state='exited', creation_time=None, session_id=None)
    session = DWORD()
    if not api.ProcessIdToSessionId(pid, ctypes.byref(session)):
        code = ctypes.get_last_error()
        if _wait(api, handle) == WAIT_OBJECT_0:
            return dict(state='exited', creation_time=None, session_id=None)
        raise _error('ProcessIdToSessionId', code)
    # The PID-based session query cannot certify another process after PID reuse.
    if _wait(api, handle) == WAIT_OBJECT_0:
        return dict(state='exited', creation_time=None, session_id=None)
    return dict(state='alive', creation_time=creation, session_id=int(session.value))


def process_probe(pid):
    """Неизвестность и access denied остаются ошибками, только exit — exited."""
    pid = _pid(pid)
    api = _api()
    handle = api.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
    if not handle:
        code = ctypes.get_last_error()
        if code == ERROR_INVALID_PARAMETER:
            return dict(state='exited', creation_time=None, session_id=None)
        raise _error('OpenProcess(probe)', code)
    try:
        return _identity(api, handle, pid)
    finally:
        _close(api, handle)


def current_session_id():
    identity = process_probe(os.getpid())
    if identity['state'] != 'alive' or identity['session_id'] is None:
        raise ValueError('Не подтверждена текущая Windows session')
    return identity['session_id']


def probe_job(name):
    """Только FILE_NOT_FOUND означает отсутствие; чужие ошибки не подавляются."""
    name = _name(name)
    api = _api()
    handle = api.OpenJobObjectW(JOB_OBJECT_QUERY, False, name)
    if not handle:
        code = ctypes.get_last_error()
        if code == ERROR_FILE_NOT_FOUND:
            return dict(state='missing', active_processes=0)
        raise _error('OpenJobObjectW(probe)', code)
    try:
        return dict(state='present', active_processes=_active(api, handle))
    finally:
        _close(api, handle)


def process_in_job(pid, name, *, creation_time=None):
    """Принадлежность точного живого процесса группе, без присоединения процесса."""
    pid, name, creation_time = _pid(pid), _name(name), _creation(creation_time)
    api = _api()
    job = api.OpenJobObjectW(JOB_OBJECT_QUERY, False, name)
    if not job:
        code = ctypes.get_last_error()
        if code == ERROR_FILE_NOT_FOUND:
            return False
        raise _error('OpenJobObjectW(membership)', code)
    try:
        process = api.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
        if not process:
            code = ctypes.get_last_error()
            if code == ERROR_INVALID_PARAMETER:
                return False
            raise _error('OpenProcess(membership)', code)
        try:
            identity = _identity(api, process, pid)
            if (identity['state'] != 'alive' or creation_time is not None
                    and identity['creation_time'] != creation_time):
                return False
            result = BOOL()
            if not api.IsProcessInJob(process, job, ctypes.byref(result)):
                raise _error('IsProcessInJob')
            return bool(result.value) and _wait(api, process) == WAIT_TIMEOUT
        finally:
            _close(api, process)
    finally:
        _close(api, job)


class WindowsJob:
    def __init__(self, name):
        self.name, self._handle = _name(name), None
        self._api = _api()
        ctypes.set_last_error(0)
        handle = self._api.CreateJobObjectW(None, self.name)
        code = ctypes.get_last_error()
        if not handle:
            raise _error('CreateJobObjectW', code)
        try:
            if code == ERROR_ALREADY_EXISTS:
                raise FileExistsError('Имя группы процессов уже занято')
            information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not self._api.SetInformationJobObject(handle, 9, ctypes.byref(information),
                    ctypes.sizeof(information)):
                raise _error('SetInformationJobObject(KILL_ON_JOB_CLOSE)')
            if not self._api.SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0):
                raise _error('SetHandleInformation(non-inheritable)')
            flags = DWORD()
            if not self._api.GetHandleInformation(handle, ctypes.byref(flags)):
                raise _error('GetHandleInformation')
            if flags.value & HANDLE_FLAG_INHERIT:
                raise ValueError('Handle группы процессов наследуется потомками')
            actual = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            returned = DWORD()
            if not self._api.QueryInformationJobObject(handle, 9, ctypes.byref(actual),
                    ctypes.sizeof(actual), ctypes.byref(returned)):
                raise _error('QueryInformationJobObject(limits)')
            forbidden = JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
            limits = actual.BasicLimitInformation.LimitFlags
            if (returned.value != ctypes.sizeof(actual)
                    or not limits & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE or limits & forbidden):
                raise ValueError('Не подтверждены kill-on-close и запрет breakaway')
            self._handle = handle
        except BaseException:
            _close(self._api, handle)
            raise

    def _open(self):
        if self._handle is None:
            raise ValueError('Группа процессов уже закрыта')
        return self._handle

    def assign(self, pid, *, creation_time=None):
        pid, creation_time = _pid(pid), _creation(creation_time)
        job = self._open()
        process = self._api.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE
            | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
        if not process:
            raise _error('OpenProcess(assign)')
        try:
            identity = _identity(self._api, process, pid)
            if (identity['state'] != 'alive' or creation_time is not None
                    and identity['creation_time'] != creation_time):
                raise ValueError('Процесс завершился или PID уже относится к другому владельцу')
            if not self._api.AssignProcessToJobObject(job, process):
                raise _error('AssignProcessToJobObject')
            result = BOOL()
            if not self._api.IsProcessInJob(process, job, ctypes.byref(result)):
                raise _error('IsProcessInJob(assign)')
            if not result.value or _wait(self._api, process) != WAIT_TIMEOUT:
                raise ValueError('Принадлежность живого worker группе не подтверждена')
            return identity
        finally:
            _close(self._api, process)

    def active_processes(self):
        return _active(self._api, self._open())

    def close(self):
        handle, self._handle = self._handle, None
        if handle is not None:
            # После неизвестного результата закрытия numeric handle нельзя повторять.
            _close(self._api, handle)

    def __enter__(self):
        self._open()
        return self

    def __exit__(self, *_):
        self.close()
