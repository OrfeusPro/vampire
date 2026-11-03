"""Проверки управляющего процесса на временных roots; updater не запускается."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).parent/'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


OWNER = load('update-owned-dispatch-v4')
LEASE = load('update-owner-lease-v4')
INDEX = load('knowledge-index').api()


class Job:
    def __init__(self, backend, name):
        self.backend, self.name, self.closed = backend, name, False
        backend.trace.append('job-created')
    def assign(self, pid, *, creation_time):
        self.backend.trace.append('assigned')
        if self.backend.deny_assign: raise OSError('assign denied')
    def close(self):
        if not self.closed:
            self.backend.trace.append('job-closed'); self.closed = True


class Backend:
    def __init__(self):
        self.trace = []; self.deny_assign = False; self.fail_drain = False
    def process_probe(self, pid):
        return dict(state='alive', creation_time='11' if pid == os.getpid() else '22', session_id=7)
    def WindowsJob(self, name): return Job(self, name)
    def current_session_id(self): return 7
    def process_in_job(self, pid, name, *, creation_time=None): return True
    def probe_job(self, name):
        if self.fail_drain: raise OSError('unknown job state')
        return dict(state='missing', active_processes=0)


class Payload(io.BytesIO):
    def __init__(self, callback): super().__init__(); self.callback = callback
    def close(self):
        if not self.closed: self.callback(self.getvalue())
        super().close()


class Child:
    def __init__(self, backend, args, *, result=True, returncode=0):
        self.backend, self.args, self.produces_result = backend, args, result
        self.pid = 2000000000; self.returncode = returncode; self.killed = False
        self.stdin = Payload(self.accept); self.stdout = io.BytesIO('Принято\n'.encode('utf-8'))
    def accept(self, raw):
        if not raw: return
        self.backend.trace.append('payload')
        assert self.backend.trace.index('assigned') < self.backend.trace.index('payload')
        value = json.loads(raw); lock = Path(value['lock']['path'])
        assert lock.is_file() and OWNER.digest(lock) == value['lock']['sha256']
        record = json.loads(lock.read_bytes()); self.epoch = record['epoch']
        if self.produces_result:
            path = self.args.root/'knowledge/update-owner-v4/epochs'/self.epoch/'result.json'
            OWNER.atomic(path, dict(epoch=self.epoch, state='completed', result=dict(state='fixture', run=None)))
    def wait(self, timeout=None): return self.returncode
    def kill(self): self.killed = True; self.backend.trace.append('unassigned-killed')


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.knowledge = self.root/'definitions'; self.knowledge.mkdir()
        self.args = SimpleNamespace(root=self.root, knowledge=self.knowledge, install=self.root/'install',
            baseline=self.root/'baseline.json', resume=None, plan_only=False, audit_only=False)
        self.args.baseline.write_text('{}')
        (self.knowledge/'update-contracts.json').write_text('{}')
        OWNER.atomic(self.knowledge/'update-owner-engine.json', dict(schema=4, recipe=OWNER.RECIPE))
        self.backend = Backend(); self.created = []
    def launcher(self, *, result=True, returncode=0):
        def launch(command, **kwargs):
            self.assertEqual(command[1:4], ['-S', '-X', 'utf8'])
            self.assertEqual(command[-1], '--worker')
            self.assertTrue(kwargs['close_fds'])
            child = Child(self.backend, self.args, result=result, returncode=returncode)
            self.created.append(child); return child
        return launch
    def run_dispatch(self, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return OWNER.dispatch(INDEX, self.args, self.root/'index.sqlite3', 'explicit',
                backend=self.backend, launcher=self.launcher(**kwargs))

    def test_selector_absent_unknown_and_enabled(self):
        self.assertTrue(OWNER.enabled(INDEX, self.args))
        OWNER.atomic(self.knowledge/'update-owner-engine.json', dict(schema=99, recipe=OWNER.RECIPE))
        with self.assertRaises(ValueError): OWNER.enabled(INDEX, self.args)
        (self.knowledge/'update-owner-engine.json').unlink()
        self.assertFalse(OWNER.enabled(INDEX, self.args))

    def test_options_roundtrip_and_mutually_exclusive_sources(self):
        value = OWNER._options(self.args, self.root/'index.sqlite3', 'explicit')
        revised = OWNER._args(value)
        self.assertEqual(revised.baseline, self.args.baseline.resolve())
        self.args.resume = self.root/'run.json'
        with self.assertRaises(ValueError): OWNER._options(self.args, self.root/'index.sqlite3', 'explicit')
        with self.assertRaises(ValueError): OWNER._options(self.args, self.root/'index.sqlite3', 'auto')

    def test_noncanonical_relative_payload_and_invalid_worker_budget_rejected(self):
        value = OWNER._options(self.args, self.root/'index.sqlite3', 'explicit')
        value['root'] = 'relative'
        with self.assertRaises(ValueError): OWNER._args(value)
        for workers in (0, 3, True):
            self.args.workers = workers
            with self.assertRaises(ValueError): OWNER._options(self.args, self.root/'index.sqlite3', 'explicit')

    def test_claim_before_payload_and_release_after_empty_group(self):
        result = self.run_dispatch()
        self.assertEqual(result['state'], 'fixture')
        self.assertFalse((self.root/'knowledge/locks/research.lock').exists())
        pointer = OWNER.checked_json(self.root/'knowledge/update-owner-v4/current.json')
        self.assertEqual(OWNER.checked_json(pointer['progress'])['state'], 'completed')
        self.assertLess(self.backend.trace.index('assigned'), self.backend.trace.index('payload'))
        self.assertLess(self.backend.trace.index('payload'), self.backend.trace.index('job-closed'))

    def test_assignment_failure_never_releases_payload_and_cleans_only_created_child(self):
        self.backend.deny_assign = True
        with self.assertRaises(OSError): self.run_dispatch()
        self.assertTrue(self.created[0].killed)
        self.assertNotIn('payload', self.backend.trace)
        self.assertFalse((self.root/'knowledge/locks/research.lock').exists())

    def test_unknown_drain_retains_lock_for_inspection(self):
        self.backend.fail_drain = True
        with self.assertRaises(OSError): self.run_dispatch()
        self.assertTrue((self.root/'knowledge/locks/research.lock').exists())

    def test_missing_or_failed_result_is_not_completed(self):
        with self.assertRaisesRegex(ValueError, 'without result'): self.run_dispatch(result=False)
        self.assertFalse((self.root/'knowledge/locks/research.lock').exists())
        with self.assertRaisesRegex(ValueError, 'failed'): self.run_dispatch(returncode=2)

    def test_stdout_unicode_can_cross_read_boundaries(self):
        class Split:
            def __init__(self): self.items = iter([bytes([value]) for value in 'Персонаж\n'.encode('utf-8')]+[b''])
            def read1(self, count): return next(self.items)
        output = io.StringIO()
        with contextlib.redirect_stdout(output): OWNER._forward(SimpleNamespace(stdout=Split()))
        self.assertEqual(output.getvalue(), 'Персонаж\n')

    def test_legacy_lock_never_launches_a_child(self):
        path = self.root/'knowledge/locks/research.lock'; path.parent.mkdir(parents=True)
        path.write_bytes(b'321')
        with self.assertRaisesRegex(ValueError, 'legacy_pid'): self.run_dispatch()
        self.assertEqual(path.read_bytes(), b'321'); self.assertFalse(self.created)

    def test_admission_rejects_missing_or_corrupt_marker(self):
        self.assertFalse(OWNER.admitted(INDEX, self.args, backend=self.backend))
        self.args._update_owner_v4 = {'unexpected': True}
        with self.assertRaises(ValueError): OWNER.admitted(INDEX, self.args, backend=self.backend)

    def admission_fixture(self):
        record = dict(schema=4, recipe=OWNER.RECIPE, epoch='a'*32, root=str(self.root.resolve()),
            guardian=dict(pid=123456789, creation_time='22', session_id=7),
            worker=dict(pid=os.getpid(), creation_time='11', session_id=7),
            job=LEASE.job_name(self.root, 'a'*32), guard=OWNER.guard(self.knowledge), operation='explicit')
        path = self.root.resolve()/'knowledge/locks/research.lock'
        OWNER.atomic(path, record)
        self.args._update_owner_v4 = dict(path=str(path), sha256=OWNER.digest(path))
        return path, record

    def test_exact_worker_guardian_and_job_admit(self):
        self.admission_fixture()
        self.assertTrue(OWNER.admitted(INDEX, self.args, backend=self.backend))

    def test_wrong_job_or_guardian_identity_rejects_admission(self):
        self.admission_fixture()
        with patch.object(self.backend, 'process_in_job', return_value=False):
            with self.assertRaises(ValueError): OWNER.admitted(INDEX, self.args, backend=self.backend)
        old = self.backend.process_probe
        with patch.object(self.backend, 'process_probe', side_effect=lambda pid:
                dict(state='alive', creation_time='999', session_id=7) if pid == 123456789 else old(pid)):
            with self.assertRaises(ValueError): OWNER.admitted(INDEX, self.args, backend=self.backend)

    def test_lock_or_tools_mutation_invalidates_admission(self):
        path, record = self.admission_fixture()
        path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaises(ValueError): OWNER.admitted(INDEX, self.args, backend=self.backend)
        OWNER.atomic(path, record)
        (self.knowledge/'update-owner-engine.json').write_bytes(b'{}')
        with self.assertRaises(ValueError): OWNER.admitted(INDEX, self.args, backend=self.backend)

    def test_status_uncertainty_remains_unknown(self):
        path = self.root/'knowledge/locks/research.lock'; path.parent.mkdir(parents=True)
        path.write_text('{bad')
        self.assertIsNone(OWNER.lock_status(self.root, backend=self.backend)['alive'])

    def test_live_output_sink_failure_cannot_report_success(self):
        with patch.object(OWNER, '_forward', side_effect=OSError('log full')):
            with self.assertRaisesRegex(ValueError, 'output'):
                self.run_dispatch()
        self.assertFalse((self.root/'knowledge/locks/research.lock').exists())


class IntegrationRoutingTests(unittest.TestCase):
    def test_owner_scaffolding_is_not_a_native_or_resource_stage_dependency(self):
        with tempfile.TemporaryDirectory() as temp:
            here = Path(temp)/'repo/phone-exit/bots/resource-tools/vampir'; here.mkdir(parents=True)
            (here/'recover-release-game-config.py').write_text("'update-owned-dispatch-v4'\n")
            (here/'update-owned-dispatch-v4.py').write_text("'unrelated-native-cases'\n")
            (here/'unrelated-native-cases.py').write_text('sentinel=1\n')
            index = SimpleNamespace(HERE=here, digest=INDEX.digest,
                extension=lambda name:SimpleNamespace(runtime_inputs=lambda:{}))
            groups = load('update-run').execution_inputs(index)
            for value in groups.values():
                self.assertNotIn(str((here/'update-owned-dispatch-v4.py').resolve()), value)
                self.assertNotIn(str((here/'unrelated-native-cases.py').resolve()), value)

    def test_auto_dispatches_before_selection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root/'update-owner-engine.json').write_text('{}')
            args = SimpleNamespace(knowledge=root)
            owner = SimpleNamespace(enabled=lambda i, a: True, admitted=lambda i, a: False,
                dispatch=lambda i, a, d, op: dict(operation=op))
            index = SimpleNamespace(extension=lambda name: owner)
            auto = load('update-auto')
            with patch.object(auto, 'select', side_effect=AssertionError('selection ran too early')):
                self.assertEqual(auto.execute(index, args, root/'index'), {'operation': 'auto'})

    def test_explicit_dispatches_before_resume_and_engine(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root/'update-owner-engine.json').write_text('{}')
            args = SimpleNamespace(knowledge=root)
            owner = SimpleNamespace(enabled=lambda i, a: True, admitted=lambda i, a: False,
                dispatch=lambda i, a, d, op: dict(operation=op))
            index = SimpleNamespace(extension=lambda name: owner)
            self.assertEqual(load('research-update').update(index, args, root/'index'), {'operation': 'explicit'})

    def test_run_uses_checked_worker_without_second_legacy_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root/'update-owner-engine.json').write_text('{}')
            args = SimpleNamespace(knowledge=root)
            owner = SimpleNamespace(enabled=lambda i, a: True, admitted=lambda i, a: True)
            index = SimpleNamespace(extension=lambda name: owner)
            run = load('update-run')
            with patch.object(run, 'run_locked', return_value={'fixture': 'ready'}) as guarded:
                self.assertEqual(run.run(index, args, root/'index'), {'fixture': 'ready'})
                guarded.assert_called_once()

    def watcher_fixture(self, folder, observation):
        watch = load('update-watch')
        path = folder/('result-'+'a'*24+'.json')
        state = dict(child=dict(pid=42, creation_time='11', recipe=watch.MANAGED_CHILD_RECIPE), result_path=str(path))
        backend = SimpleNamespace(process_probe=lambda pid: observation)
        index = SimpleNamespace(read_json=INDEX.read_json, extension=lambda name: backend)
        return watch, path, state, index

    def test_watcher_reattaches_live_exact_worker(self):
        with tempfile.TemporaryDirectory() as temp:
            watch, path, state, index = self.watcher_fixture(Path(temp), dict(state='alive', creation_time='11', session_id=7))
            child, result_path, result, interrupted = watch.previous_child(index, Path(temp), state)
            self.assertIsNone(child.poll()); self.assertEqual(result_path, path.resolve())
            self.assertFalse(interrupted); self.assertIsNone(result)
            with self.assertRaises(subprocess.TimeoutExpired): child.wait(timeout=0)

    def test_watcher_recovers_completed_result_and_marks_missing_as_interrupted(self):
        with tempfile.TemporaryDirectory() as temp:
            watch, path, state, index = self.watcher_fixture(Path(temp), dict(state='exited', creation_time=None, session_id=None))
            child, _, result, interrupted = watch.previous_child(index, Path(temp), state)
            self.assertIsNone(child); self.assertTrue(interrupted); self.assertEqual(result['state'], 'interrupted')
            OWNER.atomic(path, dict(state='needs_review'))
            _, _, result, interrupted = watch.previous_child(index, Path(temp), state)
            self.assertFalse(interrupted); self.assertEqual(result['state'], 'needs_review')

    def test_watcher_unknown_process_or_unsafe_result_path_blocks(self):
        with tempfile.TemporaryDirectory() as temp:
            watch, path, state, index = self.watcher_fixture(Path(temp), dict(state='unknown'))
            with self.assertRaises(ValueError): watch.previous_child(index, Path(temp), state)
            state['result_path'] = str(Path(temp).parent/'foreign.json')
            with self.assertRaises(ValueError): watch.previous_child(index, Path(temp), state)

    def test_interrupted_retry_survives_another_watcher_stop_before_quiet_period(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)/'watch'; folder.mkdir()
            watch, path, state, index = self.watcher_fixture(folder, dict(state='exited', creation_time=None, session_id=None))
            state.update(state='updating', owner=None, attempted_identity='old', attempted_definitions='defs')
            args = SimpleNamespace(root=Path(temp), knowledge=Path(temp), install=Path(temp)/'install')
            watch.save_state(INDEX, folder, state)
            fake_index = SimpleNamespace(**{**vars(INDEX), 'extension':lambda name:
                index.extension(name) if name == 'update-process-group-v4' else INDEX.extension(name)})
            with patch.object(watch, 'folder_for', return_value=folder), patch.object(watch, 'process_creation', return_value='44'):
                stopped = watch.watch(fake_index, args, stop_after=0, clock=lambda:0,
                    sleep=lambda _:None, launcher=lambda *_:self.fail('launch before quiet period'))
            self.assertTrue(stopped['retry_interrupted']); self.assertIsNone(stopped['child'])

    def test_reattached_worker_exit_without_result_retries_once_after_quiet(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'watch';folder.mkdir()
            watch, path, state, index=self.watcher_fixture(folder,dict(state='alive',creation_time='11',session_id=7))
            auto=SimpleNamespace(select_baseline=lambda *_:(None,dict(files=[])),inventory=lambda *_:{'file':'same'},
                fingerprint=load('update-auto').fingerprint,canonical=OWNER.canonical)
            state.update(state='updating',owner=None,attempted_identity=auto.fingerprint({'file':'same'}),attempted_definitions='defs')
            watch.save_state(INDEX,folder,state)
            args=SimpleNamespace(root=Path(temp),knowledge=Path(temp),install=Path(temp)/'install')
            observations=iter([dict(state='alive',creation_time='11',session_id=7),
                dict(state='exited',creation_time=None,session_id=None)])
            backend=SimpleNamespace(process_probe=lambda pid:next(observations))
            fake=SimpleNamespace(**{**vars(INDEX),'extension':lambda name:
                backend if name=='update-process-group-v4' else auto if name=='update-auto' else INDEX.extension(name)})
            ticks=[0];launches=[]
            class Completed:
                pid=43;returncode=0
                def poll(self):return 0
                def wait(self,timeout=None):return 0
            def launch(command,**kwargs):
                self.assertGreaterEqual(ticks[0],120)
                result=Path(command[command.index('--result')+1]);OWNER.atomic(result,dict(state='needs_review'))
                launches.append(result);return Completed()
            with patch.object(watch,'folder_for',return_value=folder),patch.object(watch,'process_creation',return_value='44'),\
                    patch.object(watch,'definition_hint',return_value='defs'):
                final=watch.watch(fake,args,clock=lambda:ticks[0],sleep=lambda _:ticks.__setitem__(0,ticks[0]+60),
                    launcher=launch,stop_after=360)
            self.assertEqual(len(launches),1);self.assertFalse(final['retry_interrupted'])
            self.assertEqual(final['last_result']['state'],'needs_review')

    def test_stop_drain_persists_result_written_during_wait(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'watch';folder.mkdir()
            watch,path,state,index=self.watcher_fixture(folder,dict(state='alive',creation_time='11',session_id=7))
            state.update(state='updating',owner=None,attempted_identity='same',attempted_definitions='defs')
            watch.save_state(INDEX,folder,state)
            args=SimpleNamespace(root=Path(temp),knowledge=Path(temp),install=Path(temp)/'install')
            backend=SimpleNamespace(process_probe=lambda _:dict(state='alive',creation_time='11',session_id=7))
            fake=SimpleNamespace(**{**vars(INDEX),'extension':lambda name:
                backend if name=='update-process-group-v4' else INDEX.extension(name)})
            expected=dict(state='needs_review',run='saved-fixture-journal')
            with patch.object(watch,'folder_for',return_value=folder),patch.object(watch,'process_creation',return_value='44'),\
                    patch.object(watch.ObservedChild,'wait',side_effect=lambda:OWNER.atomic(path,expected)):
                def interrupted_sleep(_):raise KeyboardInterrupt
                with self.assertRaises(KeyboardInterrupt):
                    watch.watch(fake,args,stop_after=0,clock=lambda:0,sleep=interrupted_sleep,
                        launcher=lambda *_:self.fail('Stop launched updater'))
            stopped=watch.read_state(INDEX,folder)
            self.assertEqual(stopped['last_result'],expected)
            self.assertEqual(watch.read_state(INDEX,folder)['last_result'],expected)
            self.assertIsNone(stopped['child'])
            self.assertEqual(watch.previous_child(fake,folder,stopped),(None,None,None,False))


@unittest.skipUnless(os.name == 'nt', 'Real Windows managed-process fixtures')
class WindowsDispatcherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()/'resources'
        self.here = Path(self.temp.name).resolve()/'repo/phone-exit/bots/resource-tools/vampir'
        self.here.mkdir(parents=True); self.knowledge = self.root/'definitions'; self.knowledge.mkdir(parents=True)
        for name in ('update-owned-dispatch-v4', 'update-owner-lease-v4', 'update-process-group-v4'):
            (self.here/(name+'.py')).write_bytes((HERE/(name+'.py')).read_bytes())
        (self.here/'knowledge-index.py').write_text(
            'from pathlib import Path\nimport importlib.util\nfrom types import SimpleNamespace\n'
            'def extension(name):\n s=importlib.util.spec_from_file_location(name,Path(__file__).parent/(name+".py"));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m\n'
            'def api():return SimpleNamespace(extension=extension)\n', encoding='utf-8')
        (self.here/'update-auto.py').write_text(
            'import json,os,subprocess,sys,time\nfrom pathlib import Path\n'
            'def execute(index,args,database):\n'
            ' owner=index.extension("update-owned-dispatch-v4");assert owner.admitted(index,args)\n'
            ' run=args.root/"knowledge/update-runs"/("a"*64)/"run.json";run.parent.mkdir(parents=True,exist_ok=True)\n'
            ' if not run.exists():\n'
            '  with run.open("w") as f:f.write("completed fixture stage");f.flush();os.fsync(f.fileno())\n'
            '  (args.root/"executions.txt").write_text("1")\n'
            ' args.journal_created(run,{"source_sha256":"b"*64})\n'
            ' if (args.root/"wait.flag").exists():\n'
            '  child=subprocess.Popen([sys.executable,"-S","-c","import time;time.sleep(120)"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=0x08000000)\n'
            '  (args.root/"descendant.json").write_text(json.dumps({"pid":child.pid,"identity":index.extension("update-process-group-v4").process_probe(child.pid)}))\n'
            '  time.sleep(120)\n'
            ' return {"state":"fixture","run":str(run)}\n', encoding='utf-8')
        OWNER.atomic(self.knowledge/'update-owner-engine.json', dict(schema=4, recipe=OWNER.RECIPE))
        spec = importlib.util.spec_from_file_location('temporary_owner_v4', self.here/'update-owned-dispatch-v4.py')
        self.owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.owner)
        self.args = SimpleNamespace(root=self.root, knowledge=self.knowledge, install=self.root/'install',
            baseline=None, resume=None, plan_only=False, audit_only=False)
        self.backend = self.owner.load('update-process-group-v4')

    def dispatch(self, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return self.owner.dispatch(None, self.args, self.root/'index.sqlite3', 'auto', **kwargs)

    def test_real_worker_site_hooks_only_after_assignment_and_journal_linked(self):
        hook = Path(self.temp.name).resolve()/'hooks'; hook.mkdir()
        marker = hook/'site.marker'
        (hook/'sitecustomize.py').write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("assigned")\n', encoding='utf-8')
        real_backend = self.backend
        class CheckedJob:
            def __init__(inner, name): inner.job = real_backend.WindowsJob(name)
            def assign(inner, pid, **kwargs):
                self.assertFalse(marker.exists(), 'site hook escaped startup gate')
                return inner.job.assign(pid, **kwargs)
            def close(inner): inner.job.close()
        proxy = SimpleNamespace(**vars(real_backend)); proxy.WindowsJob = CheckedJob
        with patch.dict(os.environ, {'PYTHONPATH':str(hook)}):
            result = self.dispatch(backend=proxy)
        self.assertEqual(result['state'], 'fixture'); self.assertTrue(marker.exists())
        state = OWNER.checked_json(self.root/'knowledge/update-owner-v4/current.json')
        self.assertEqual(OWNER.checked_json(state['progress'])['run'], result['run'])
        self.assertFalse((self.root/'knowledge/locks/research.lock').exists())

    def test_real_guardian_crash_closes_descendants_and_resumes_completed_fixture_stage(self):
        (self.root/'wait.flag').write_text('wait')
        script = Path(self.temp.name).resolve()/'guardian.py'
        script.write_text('import importlib.util\nfrom pathlib import Path\nfrom types import SimpleNamespace\n'
            's=importlib.util.spec_from_file_location("owner",'+repr(str(self.here/'update-owned-dispatch-v4.py'))+');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n'
            'root=Path('+repr(str(self.root))+');args=SimpleNamespace(root=root,knowledge=root/"definitions",install=root/"install",baseline=None,resume=None,plan_only=False,audit_only=False)\n'
            'm.dispatch(None,args,root/"index.sqlite3","auto")\n', encoding='utf-8')
        with tempfile.TemporaryFile() as output:
            guardian = subprocess.Popen([os.sys.executable, '-X', 'utf8', str(script)], stdout=output, stderr=output,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            self.addCleanup(lambda: guardian.kill() if guardian.poll() is None else None)
            deadline = time.monotonic()+15
            while not (self.root/'descendant.json').exists():
                if guardian.poll() is not None or time.monotonic()>deadline:
                    output.seek(0); self.fail(output.read().decode('utf-8', errors='replace'))
                time.sleep(0.02)
            descendant = OWNER.checked_json(self.root/'descendant.json')
            state = OWNER.checked_json(self.root/'knowledge/update-owner-v4/current.json')
            run = Path(OWNER.checked_json(state['progress'])['run']); before = run.read_bytes()
            guardian.kill(); guardian.wait(timeout=10)
            deadline = time.monotonic()+10
            while self.backend.probe_job(state['owner']['job'])['active_processes']:
                if time.monotonic()>deadline: self.fail('Owned dummy descendants remained active')
                time.sleep(0.02)
            expected = dict(pid=descendant['pid'], creation_time=descendant['identity']['creation_time'],
                session_id=descendant['identity']['session_id'])
            while OWNER.same_process(self.backend.process_probe(descendant['pid']), expected):
                if time.monotonic()>deadline: self.fail('Known dummy descendant did not finish termination')
                time.sleep(0.02)
            (self.root/'wait.flag').unlink()
            result = self.dispatch()
            current = OWNER.checked_json(self.root/'knowledge/update-owner-v4/current.json')
            self.assertIsNotNone(current['recovered'])
            self.assertEqual(result['state'], 'fixture')
            self.assertEqual(run.read_bytes(), before)
            self.assertEqual((self.root/'executions.txt').read_text(), '1')


if __name__ == '__main__':
    unittest.main()
