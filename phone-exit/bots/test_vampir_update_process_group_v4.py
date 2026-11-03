"""Windows group ABI/error checks and owned temporary process regressions only."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

HERE = Path(__file__).parent/'resource-tools/vampir'
SPEC = importlib.util.spec_from_file_location('update_process_group_v4_tested', HERE/'update-process-group-v4.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
NAME = 'Local\\PhoneExit-Vampir-Update-v4-test-'+uuid.uuid4().hex


class FakeAPI:
    def __init__(self):
        self.error = 0
        self.failures = {}
        self.closed = []
        self.calls = []
        self.existing = False
        self.inherited = 0
        self.actual_flags = M.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        self.partial_query = False
        self.active = 2
        self.waits = []
        self.membership = True
        self.ctime = 77
        self.session = 3

    def checked(self, name):
        self.calls.append(name)
        if name in self.failures:
            self.error = self.failures[name]
            return False
        return True

    def CreateJobObjectW(self, security, name):
        self.security, self.name = security, name
        if not self.checked('CreateJobObjectW'):
            return None
        self.error = M.ERROR_ALREADY_EXISTS if self.existing else 0
        return 101

    def OpenJobObjectW(self, access, inherit, name):
        self.job_access, self.job_inherit, self.name = access, inherit, name
        return 101 if self.checked('OpenJobObjectW') else None

    def SetInformationJobObject(self, handle, kind, value, size):
        self.requested_flags = value._obj.BasicLimitInformation.LimitFlags
        self.limit_kind, self.limit_bytes = kind, size
        return self.checked('SetInformationJobObject')

    def QueryInformationJobObject(self, handle, kind, value, size, returned):
        if not self.checked('QueryInformationJobObject'):
            return False
        returned._obj.value = size-1 if self.partial_query else size
        if kind == 9:
            value._obj.BasicLimitInformation.LimitFlags = self.actual_flags
        elif kind == 1:
            value._obj.ActiveProcesses = self.active
            value._obj.TotalProcesses = self.active+10
        else:
            raise AssertionError('Unexpected query kind')
        return True

    def SetHandleInformation(self, handle, mask, flags):
        self.handle_mask, self.handle_flags = mask, flags
        return self.checked('SetHandleInformation')

    def GetHandleInformation(self, handle, flags):
        flags._obj.value = self.inherited
        return self.checked('GetHandleInformation')

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return self.checked('CloseHandle')

    def OpenProcess(self, access, inherit, pid):
        self.process_access, self.process_inherit, self.pid = access, inherit, pid
        return 202 if self.checked('OpenProcess') else None

    def GetProcessTimes(self, handle, *values):
        if not self.checked('GetProcessTimes'):
            return False
        values[0]._obj.dwLowDateTime = self.ctime & 0xFFFFFFFF
        values[0]._obj.dwHighDateTime = self.ctime >> 32
        return True

    def WaitForSingleObject(self, handle, timeout):
        self.calls.append('WaitForSingleObject')
        return self.waits.pop(0) if self.waits else M.WAIT_TIMEOUT

    def ProcessIdToSessionId(self, pid, value):
        value._obj.value = self.session
        return self.checked('ProcessIdToSessionId')

    def AssignProcessToJobObject(self, job, process):
        return self.checked('AssignProcessToJobObject')

    def IsProcessInJob(self, process, job, value):
        value._obj.value = self.membership
        return self.checked('IsProcessInJob')


class GroupUnitTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI()
        self.patches = [patch.object(M, '_api', return_value=self.api),
            patch.object(M.ctypes, 'get_last_error', lambda: self.api.error, create=True),
            patch.object(M.ctypes, 'set_last_error', self.set_error, create=True)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def set_error(self, code):
        self.api.error = code

    def test_abi_structure_sizes_and_offsets(self):
        self.assertEqual(ctypes.sizeof(M.FILETIME), 8)
        self.assertEqual(ctypes.sizeof(M.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION), 48)
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(M.JOBOBJECT_BASIC_LIMIT_INFORMATION), 64)
            self.assertEqual(ctypes.sizeof(M.JOBOBJECT_EXTENDED_LIMIT_INFORMATION), 144)
            self.assertEqual(M.JOBOBJECT_BASIC_LIMIT_INFORMATION.Affinity.offset, 48)
            self.assertEqual(M.JOBOBJECT_EXTENDED_LIMIT_INFORMATION.ProcessMemoryLimit.offset, 112)

    def test_invalid_names_rejected_before_open(self):
        for value in (None, '', 'Global\\other', 'Local\\a\\b', 'Local\\with space', 'Local\\'+'a'*201):
            with self.subTest(value=value), self.assertRaises(ValueError):
                M.WindowsJob(value)
        self.assertEqual(self.api.calls, [])

    def test_invalid_pid_and_creation_rejected(self):
        for value in (None, True, 0, -1, 2**32):
            with self.subTest(pid=value), self.assertRaises(ValueError):
                M.process_probe(value)
        for value in (77, '', '0', '077', '-1', str(2**64)):
            with self.subTest(creation=value), self.assertRaises(ValueError):
                M.process_in_job(42, NAME, creation_time=value)
        self.assertEqual(self.api.calls, [])

    def test_new_job_has_kill_no_breakaway_and_noninherited_handle(self):
        with M.WindowsJob(NAME) as job:
            self.assertEqual(job.active_processes(), 2)
            self.assertEqual(self.api.requested_flags, M.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
            self.assertIsNone(self.api.security)
            self.assertEqual((self.api.handle_mask, self.api.handle_flags), (1, 0))
        self.assertEqual(self.api.closed, [101])

    def test_existing_name_is_never_reconfigured(self):
        self.api.existing = True
        with self.assertRaises(FileExistsError):
            M.WindowsJob(NAME)
        self.assertNotIn('SetInformationJobObject', self.api.calls)
        self.assertEqual(self.api.closed, [101])

    def test_create_error_does_not_close_unowned_handle(self):
        self.api.failures['CreateJobObjectW'] = 5
        with self.assertRaises(OSError):
            M.WindowsJob(NAME)
        self.assertEqual(self.api.closed, [])

    def test_each_setup_error_closes_new_job_handle(self):
        for function in ('SetInformationJobObject', 'SetHandleInformation',
                'GetHandleInformation', 'QueryInformationJobObject'):
            with self.subTest(function=function):
                self.api = FakeAPI(); self.api.failures[function] = 5
                with patch.object(M, '_api', return_value=self.api), self.assertRaises(OSError):
                    M.WindowsJob(NAME)
                self.assertEqual(self.api.closed, [101])

    def test_inherited_handle_rejected(self):
        self.api.inherited = M.HANDLE_FLAG_INHERIT
        with self.assertRaises(ValueError):
            M.WindowsJob(NAME)
        self.assertEqual(self.api.closed, [101])

    def test_breakaway_or_missing_kill_or_partial_limits_rejected(self):
        for flags in (0, M.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | M.JOB_OBJECT_LIMIT_BREAKAWAY_OK,
                M.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | M.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK):
            with self.subTest(flags=flags):
                self.api.actual_flags = flags
                with self.assertRaises(ValueError):
                    M.WindowsJob(NAME)
        self.api.actual_flags = M.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; self.api.partial_query = True
        with self.assertRaises(ValueError):
            M.WindowsJob(NAME)

    def test_close_idempotent_and_queries_after_close_rejected(self):
        job = M.WindowsJob(NAME); job.close(); job.close()
        self.assertEqual(self.api.closed, [101])
        with self.assertRaises(ValueError):
            job.active_processes()
        with self.assertRaises(ValueError):
            job.assign(42)

    def test_close_failure_detaches_handle_and_never_retries_unknown_result(self):
        job = M.WindowsJob(NAME); self.api.failures['CloseHandle'] = 6
        with self.assertRaises(OSError):
            job.close()
        self.assertIsNone(job._handle)
        self.api.failures.clear(); job.close()
        self.assertEqual(self.api.closed, [101])
        with self.assertRaises(ValueError):
            job.active_processes()

    def test_active_query_error_and_partial_data_are_not_empty_group(self):
        with M.WindowsJob(NAME) as job:
            self.api.failures['QueryInformationJobObject'] = 5
            with self.assertRaises(OSError):
                job.active_processes()
            self.api.failures.clear(); self.api.partial_query = True
            with self.assertRaises(ValueError):
                job.active_processes()

    def test_process_alive_identity_and_query_handle_rights(self):
        self.api.ctime = (5 << 32)+77
        value = M.process_probe(42)
        self.assertEqual(value, dict(state='alive', creation_time=str(self.api.ctime), session_id=3))
        self.assertEqual(self.api.process_access, M.PROCESS_QUERY_LIMITED_INFORMATION | M.SYNCHRONIZE)
        self.assertFalse(self.api.process_inherit)
        self.assertEqual(self.api.closed, [202])

    def test_exited_process_is_not_queried_by_reused_pid_for_session(self):
        self.api.waits = [M.WAIT_OBJECT_0]
        self.assertEqual(M.process_probe(42), dict(state='exited', creation_time=None, session_id=None))
        self.assertNotIn('ProcessIdToSessionId', self.api.calls)

    def test_missing_pid_only_invalid_parameter_is_exited(self):
        self.api.failures['OpenProcess'] = M.ERROR_INVALID_PARAMETER
        self.assertEqual(M.process_probe(42), dict(state='exited', creation_time=None, session_id=None))
        self.assertEqual(self.api.closed, [])

    def test_access_denied_and_unknown_open_are_not_process_exit(self):
        for code in (5, 6, 0):
            with self.subTest(code=code):
                self.api.failures['OpenProcess'] = code
                with self.assertRaises(OSError):
                    M.process_probe(42)

    def test_failed_get_times_closes_process(self):
        self.api.failures['GetProcessTimes'] = 5
        with self.assertRaises(OSError):
            M.process_probe(42)
        self.assertEqual(self.api.closed, [202])

    def test_failed_live_session_query_is_unknown_not_exit(self):
        self.api.failures['ProcessIdToSessionId'] = 5
        with self.assertRaises(OSError):
            M.process_probe(42)
        self.assertEqual(self.api.closed, [202])

    def test_session_query_race_after_process_exit_discards_pid_data(self):
        self.api.failures['ProcessIdToSessionId'] = 87
        self.api.waits = [M.WAIT_TIMEOUT, M.WAIT_OBJECT_0]
        self.assertEqual(M.process_probe(42)['state'], 'exited')
        self.api.failures.clear(); self.api.waits = [M.WAIT_TIMEOUT, M.WAIT_OBJECT_0]
        self.assertIsNone(M.process_probe(42)['session_id'])

    def test_failed_or_unexpected_wait_is_not_exit(self):
        for value in (M.WAIT_FAILED, 0x80):
            with self.subTest(wait=value):
                self.api.waits = [value]
                with self.assertRaises(OSError):
                    M.process_probe(42)

    def test_job_probe_active_and_zero_close_query_handle(self):
        for active in (2, 0):
            self.api.active = active
            self.assertEqual(M.probe_job(NAME), dict(state='present', active_processes=active))
        self.assertEqual(self.api.closed, [101, 101])
        self.assertEqual(self.api.job_access, M.JOB_OBJECT_QUERY)
        self.assertFalse(self.api.job_inherit)

    def test_job_probe_only_not_found_is_missing(self):
        self.api.failures['OpenJobObjectW'] = 2
        self.assertEqual(M.probe_job(NAME), dict(state='missing', active_processes=0))
        for code in (5, 6, 0):
            with self.subTest(code=code):
                self.api.failures['OpenJobObjectW'] = code
                with self.assertRaises(OSError):
                    M.probe_job(NAME)

    def test_job_probe_query_failure_closes_handle(self):
        self.api.failures['QueryInformationJobObject'] = 5
        with self.assertRaises(OSError):
            M.probe_job(NAME)
        self.assertEqual(self.api.closed, [101])

    def test_assign_exact_creation_identity_and_handle_rights(self):
        with M.WindowsJob(NAME) as job:
            self.assertEqual(job.assign(42, creation_time='77')['creation_time'], '77')
            self.assertEqual(self.api.closed, [202])
            self.assertEqual(self.api.process_access, M.PROCESS_SET_QUOTA | M.PROCESS_TERMINATE
                | M.PROCESS_QUERY_LIMITED_INFORMATION | M.SYNCHRONIZE)
            self.assertFalse(self.api.process_inherit)

    def test_assign_reused_pid_or_exited_is_not_assigned(self):
        with M.WindowsJob(NAME) as job:
            with self.assertRaises(ValueError):
                job.assign(42, creation_time='78')
            self.api.waits = [M.WAIT_OBJECT_0]
            with self.assertRaises(ValueError):
                job.assign(42, creation_time='77')
            self.assertNotIn('AssignProcessToJobObject', self.api.calls)
            self.assertEqual(self.api.closed, [202, 202])

    def test_assign_and_membership_errors_close_process_handle(self):
        with M.WindowsJob(NAME) as job:
            for function in ('AssignProcessToJobObject', 'IsProcessInJob'):
                with self.subTest(function=function):
                    self.api.failures = {function: 5}
                    with self.assertRaises(OSError):
                        job.assign(42, creation_time='77')
            self.api.failures.clear(); self.api.membership = False
            with self.assertRaises(ValueError):
                job.assign(42, creation_time='77')
            self.assertEqual(self.api.closed, [202, 202, 202])

    def test_membership_checks_exact_creation_and_both_handles_closed(self):
        self.assertTrue(M.process_in_job(42, NAME, creation_time='77'))
        self.assertEqual(self.api.closed, [202, 101])
        self.api.calls.clear()
        self.assertFalse(M.process_in_job(42, NAME, creation_time='78'))
        self.assertNotIn('IsProcessInJob', self.api.calls)

    def test_membership_missing_job_or_process_returns_false(self):
        self.api.failures['OpenJobObjectW'] = 2
        self.assertFalse(M.process_in_job(42, NAME))
        self.assertNotIn('OpenProcess', self.api.calls)
        self.api.failures = {'OpenProcess': 87}
        self.assertFalse(M.process_in_job(42, NAME))
        self.assertEqual(self.api.closed, [101])

    def test_membership_unknown_failures_are_not_false(self):
        for function in ('OpenJobObjectW', 'OpenProcess', 'IsProcessInJob'):
            with self.subTest(function=function):
                self.api.failures = {function: 5}
                with self.assertRaises(OSError):
                    M.process_in_job(42, NAME)

    def test_membership_process_exiting_after_query_returns_false(self):
        self.api.waits = [M.WAIT_TIMEOUT, M.WAIT_TIMEOUT, M.WAIT_OBJECT_0]
        self.assertFalse(M.process_in_job(42, NAME, creation_time='77'))

    def test_current_session_requires_confirmed_alive_identity(self):
        with patch.object(M, 'process_probe', return_value=dict(state='alive', session_id=5)) as probe:
            self.assertEqual(M.current_session_id(), 5)
            probe.assert_called_once_with(os.getpid())
        with patch.object(M, 'process_probe', return_value=dict(state='exited', session_id=None)):
            with self.assertRaises(ValueError):
                M.current_session_id()


WORKER = '''import sys
if sys.stdin.buffer.read(1) != b'1':
 sys.exit(2)
import subprocess,time,json,os
from pathlib import Path
child=subprocess.Popen([sys.executable,'-S','-X','utf8','-c','import time;time.sleep(40)'],
 stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
 creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),close_fds=True)
Path(sys.argv[1]).write_text(json.dumps({'worker':os.getpid(),'child':child.pid}),'utf-8')
time.sleep(40)
'''


@unittest.skipUnless(os.name == 'nt', 'Windows Job Object integration')
class WindowsGroupTests(unittest.TestCase):
    def wait_notice(self, path, process, seconds=8):
        deadline = time.monotonic()+seconds
        while time.monotonic() < deadline:
            if path.is_file():
                try:
                    return json.loads(path.read_text('utf-8'))
                except (ValueError, OSError):
                    pass
            if process.poll() is not None:
                self.fail('Own temporary worker exited before its notice')
            time.sleep(.02)
        self.fail('Own temporary worker notice timed out')

    def assert_identity_exited(self, pid, creation_time):
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            observed = M.process_probe(pid)
            if observed['state'] == 'exited' or observed['creation_time'] != creation_time:
                return
            time.sleep(.02)
        self.fail('Own temporary process survived job cleanup')

    def test_actual_kernel_signatures_and_current_process_probe(self):
        api = M._api()
        self.assertEqual(api.CreateJobObjectW.restype, ctypes.c_void_p)
        self.assertEqual(api.OpenProcess.restype, ctypes.c_void_p)
        self.assertEqual(len(api.GetProcessTimes.argtypes), 5)
        observed = M.process_probe(os.getpid())
        self.assertEqual(observed['state'], 'alive')
        self.assertTrue(observed['creation_time'].isdigit())
        self.assertEqual(observed['session_id'], M.current_session_id())

    def test_actual_gated_worker_descendant_membership_and_last_handle_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); script = folder/'worker.py'; notice = folder/'notice.json'
            script.write_text(WORKER, encoding='utf-8')
            name = 'Local\\PhoneExit-Vampir-Update-v4-test-'+uuid.uuid4().hex
            job = M.WindowsJob(name)
            worker = subprocess.Popen([sys.executable, '-S', '-X', 'utf8', str(script), str(notice)],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW, close_fds=True)
            try:
                identity = M.process_probe(worker.pid)
                job.assign(worker.pid, creation_time=identity['creation_time'])
                worker.stdin.write(b'1'); worker.stdin.close()
                value = self.wait_notice(notice, worker)
                child = M.process_probe(value['child'])
                self.assertTrue(M.process_in_job(worker.pid, name, creation_time=identity['creation_time']))
                self.assertTrue(M.process_in_job(value['child'], name, creation_time=child['creation_time']))
                # Windows may also assign each console host to the owned tree.
                self.assertGreaterEqual(job.active_processes(), 2)
                self.assertGreaterEqual(M.probe_job(name)['active_processes'], 2)
                with self.assertRaises(FileExistsError):
                    M.WindowsJob(name)
                self.assertGreaterEqual(job.active_processes(), 2)
                job.close(); worker.wait(timeout=5)
                self.assert_identity_exited(value['child'], child['creation_time'])
                self.assertEqual(M.probe_job(name), dict(state='missing', active_processes=0))
            finally:
                job.close()
                if worker.poll() is None:
                    worker.terminate(); worker.wait(timeout=5)
                if worker.stdin and not worker.stdin.closed:
                    worker.stdin.close()

    def test_actual_guardian_crash_closes_handle_and_terminates_group(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); worker_script = folder/'worker.py'; worker_notice = folder/'worker.json'
            guardian_script = folder/'guardian.py'; ready = folder/'guardian.json'
            worker_script.write_text(WORKER, encoding='utf-8')
            guardian_script.write_text('''import importlib.util,sys,subprocess,json,time,os
from pathlib import Path
spec=importlib.util.spec_from_file_location('own_job',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
job=m.WindowsJob(sys.argv[2])
worker=subprocess.Popen([sys.executable,'-S','-X','utf8',sys.argv[3],sys.argv[4]],stdin=subprocess.PIPE,
 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW,close_fds=True)
identity=m.process_probe(worker.pid);job.assign(worker.pid,creation_time=identity['creation_time'])
worker.stdin.write(b'1');worker.stdin.close()
Path(sys.argv[5]).write_text(json.dumps({'guardian':os.getpid(),'worker':worker.pid,'creation_time':identity['creation_time']}),'utf-8')
time.sleep(40)
''', encoding='utf-8')
            name = 'Local\\PhoneExit-Vampir-Update-v4-test-'+uuid.uuid4().hex
            guardian = subprocess.Popen([sys.executable, '-S', '-X', 'utf8', str(guardian_script),
                str(HERE/'update-process-group-v4.py'), name, str(worker_script), str(worker_notice), str(ready)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW, close_fds=True)
            try:
                value = self.wait_notice(ready, guardian)
                descendants = self.wait_notice(worker_notice, guardian)
                child_identity = M.process_probe(descendants['child'])
                self.assertGreaterEqual(M.probe_job(name)['active_processes'], 2)
                guardian.terminate(); guardian.wait(timeout=5)
                self.assert_identity_exited(value['worker'], value['creation_time'])
                self.assert_identity_exited(descendants['child'], child_identity['creation_time'])
                self.assertEqual(M.probe_job(name), dict(state='missing', active_processes=0))
            finally:
                if guardian.poll() is None:
                    guardian.terminate(); guardian.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
