"""Offline auto-selection and watcher ownership policy; no game or real update."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

TOOLS=Path(__file__).parent/'resource-tools/vampir'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),TOOLS/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


INDEX=load('knowledge-index').api()
AUTO=load('update-auto');WATCH=load('update-watch');WORKFLOW=load('research-workflow')


class AutoSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.install=self.root/'install';self.knowledge=self.root/'definitions';self.knowledge.mkdir()
        self.exe=self.install/'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'
        self.exe.parent.mkdir(parents=True);self.exe.write_bytes(b'fake source')
        self.archive=self.install/'ProjectRED/Content/Paks/game.pak';self.archive.parent.mkdir(parents=True)
        self.archive.write_bytes(b'archive')
        self.args=SimpleNamespace(root=self.root,knowledge=self.knowledge,install=self.install,
            auto=True,resume=None,baseline=None,plan_only=False,audit_only=False)
        definitions=patch.object(AUTO,'definition_inputs',side_effect=lambda index,knowledge:
            {str(path.resolve()):INDEX.digest(path) for path in Path(knowledge).glob('*.json')})
        definitions.start();self.addCleanup(definitions.stop)
        self.manifest=dict(schema=1,source=str(self.install.resolve()),full_archive_coverage=True,
            exe=dict(path=str(self.exe.resolve()),sha256=INDEX.digest(self.exe)),
            files=[dict(path=str(self.archive.resolve()),current=dict(sha256=INDEX.digest(self.archive)))])

    def save_baseline(self,value=None):
        return WORKFLOW.snapshot(self.root,'update-audits',value or self.manifest)

    def test_latest_complete_same_install_inventory_and_corrupt_rejected(self):
        correct=self.save_baseline()
        incomplete={**self.manifest,'full_archive_coverage':False};self.save_baseline(incomplete)
        other={**self.manifest,'source':str(self.root/'other')};self.save_baseline(other)
        corrupt=self.root/'knowledge/update-audits'/('f'*64)/'manifest.json'
        corrupt.parent.mkdir();corrupt.write_text(json.dumps(self.manifest))
        actual,_=AUTO.select_baseline(INDEX,self.args)
        self.assertEqual(actual,correct)

    def test_unsafe_archive_or_missing_full_sha_not_accepted(self):
        for value in ({**self.manifest,'files':[dict(path=str(self.root/'outside.pak'),current=dict(sha256='a'*64))]},
                {**self.manifest,'files':[dict(path=str(self.archive),current=dict(sample_sha256='a'*64))]}):
            self.assertFalse(AUTO.baseline_valid(value,self.install))

    def test_resume_requires_same_full_source_inventory_and_definitions(self):
        self.save_baseline();selection=AUTO.select(INDEX,self.args)
        run_path=self.root/'knowledge/update-runs'/'fake'/'run.json'
        run=dict(source_sha256=INDEX.digest(self.exe),install=str(self.install.resolve()),state='needs_review')
        INDEX.extension('update-run').save(WORKFLOW,run_path,run)
        WORKFLOW.atomic(selection['receipt'],AUTO.canonical(dict(identity=selection['identity'],run=str(run_path))))
        self.assertEqual(AUTO.select(INDEX,self.args)['resume'],run_path.resolve())
        (self.knowledge/'new.json').write_text('{}')
        self.assertIsNone(AUTO.select(INDEX,self.args)['resume'])
        (self.knowledge/'new.json').unlink();self.exe.write_bytes(b'new fake source')
        self.assertIsNone(AUTO.select(INDEX,self.args)['resume'])

    def test_selection_rejects_installation_changed_during_hashing(self):
        self.save_baseline();real=AUTO.inventory;calls=[]
        def changed(*args,**kwargs):
            value=real(*args,**kwargs);calls.append(True)
            if len(calls)==2:value['changed']={}
            return value
        with patch.object(AUTO,'inventory',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'Installation changed'):AUTO.select(INDEX,self.args)

    def test_interrupted_update_retains_automatic_resume_receipt(self):
        self.save_baseline();run_path=self.root/'knowledge/update-runs'/'interrupted'/'run.json'
        def update(index,args,database):
            record=dict(source_sha256=INDEX.digest(self.exe),install=str(self.install.resolve()),state='interrupted')
            INDEX.extension('update-run').save(WORKFLOW,run_path,record)
            args.journal_created(run_path,record)
            raise KeyboardInterrupt
        adapter=SimpleNamespace(update=update,signatures=INDEX.extension('research-update').signatures)
        fake=SimpleNamespace(**{**vars(INDEX),'extension':lambda name:adapter if name=='research-update' else INDEX.extension(name)})
        with self.assertRaises(KeyboardInterrupt):AUTO.execute(fake,self.args,self.root/'index.sqlite3')
        self.assertEqual(AUTO.select(INDEX,self.args)['resume'],run_path.resolve())


class WatchPolicyTests(unittest.TestCase):
    def watch_args(self,temporary):
        return SimpleNamespace(install=Path(temporary)/'install',root=Path(temporary),knowledge=Path(temporary))

    def test_quiet_period_changed_source_and_no_unchanged_review_retry(self):
        trigger=WATCH.Trigger()
        self.assertEqual(trigger.observe('source1','defs1',0),'waiting_for_install')
        self.assertEqual(trigger.observe('source1','defs1',119),'waiting_for_install')
        self.assertEqual(trigger.observe('source1','defs1',120),'run')
        self.assertEqual(trigger.observe('source1','defs1',300),'unchanged')
        self.assertEqual(trigger.observe('source2','defs1',301),'waiting_for_install')
        self.assertEqual(trigger.observe('source2','defs1',421),'run')

    def test_definition_change_and_explicit_retry_allow_one_attempt(self):
        trigger=WATCH.Trigger(0)
        self.assertEqual(trigger.observe('same','defs1',0),'run')
        self.assertEqual(trigger.observe('same','defs2',1),'run')
        self.assertEqual(trigger.observe('same','defs2',2),'unchanged')
        trigger.request_retry()
        self.assertEqual(trigger.observe('same','defs2',3),'run')
        self.assertEqual(trigger.observe('same','defs2',4),'unchanged')

    def test_process_identity_rejects_reused_pid(self):
        with patch.object(WATCH,'process_creation',return_value='new'):
            self.assertFalse(WATCH.alive(dict(pid=42,creation_time='old')))
            self.assertTrue(WATCH.alive(dict(pid=42,creation_time='new')))

    def test_event_log_is_bounded_and_status_reads_only_tail_phase(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary);path=folder/'result-fixture.events.jsonl'
            log=WATCH.EventLog(path,limit=512)
            for number in range(100):log.write(json.dumps(dict(event='update_stage',stage='phase'+str(number)))+'\n')
            self.assertLessEqual(path.stat().st_size,512)
            self.assertEqual(WATCH.last_phase(folder,dict(event_log=str(path)))['stage'],'phase99')
            with self.assertRaises(ValueError):WATCH.last_phase(folder,dict(event_log=str(folder.parent/'outside.events.jsonl')))

    def test_result_retention_excludes_active_run_and_other_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary)
            for number in range(25):
                path=folder/('result-'+format(number,'024x')+'.json');path.write_text('{}')
                path.with_suffix('.events.jsonl').write_text('{}\n')
            unrelated=folder/'owner.json';unrelated.write_text('{}')
            foreign=folder/'result-user-notes.json';foreign.write_text('keep')
            active=folder/('result-'+'f'*24+'.json');WATCH.retain_results(folder,active);active.write_text('{}')
            self.assertEqual(len(list(folder.glob('result-*.json'))),WATCH.RETAIN_RUNS+1)
            self.assertEqual(foreign.read_text(),'keep')
            self.assertTrue(unrelated.is_file());self.assertTrue(active.is_file())

    def test_owner_lock_prevents_duplicate_writer_and_releases(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary)
            with WATCH.owner_lock(folder):
                with self.assertRaises(ValueError):
                    with WATCH.owner_lock(folder):pass
            with WATCH.owner_lock(folder):pass

    def test_commands_are_scoped_to_owner_epoch_and_do_not_stop_game(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary)
            for name,value in [('old',dict(action='stop',start_token='old')),
                    ('new',dict(action='retry',start_token='new'))]:
                (folder/('command-'+('a' if name=='old' else 'b')*24+'.json')).write_bytes(AUTO.canonical(value))
            self.assertEqual(WATCH.queued_commands(INDEX,folder,'new'),['retry'])
            self.assertEqual(list(folder.glob('command-*.json')),[])

    def test_start_uses_unlimited_existing_scheduler_and_status_redacts_token(self):
        with tempfile.TemporaryDirectory() as temporary:
            args=SimpleNamespace(install=Path(temporary)/'install',root=Path(temporary),knowledge=Path(temporary),action='start')
            folder=Path(temporary)/'watch'
            with patch.object(WATCH,'folder_for',return_value=folder),patch('vampir_core.scheduled_worker.launch_scheduled',
                    return_value=dict(status='ready',pid=42)) as start:
                value=WATCH.control(INDEX,args)
                self.assertFalse(value['windows_autostart']);self.assertTrue(start.call_args.kwargs['unlimited'])
                self.assertNotIn('login',str(start.call_args))
                WATCH.save_state(INDEX,folder,dict(state='watching',owner=dict(pid=42,creation_time='new',start_token='private'),child=None))
                args.action='status'
                with patch.object(WATCH,'process_creation',return_value='new'):
                    self.assertNotIn('start_token',WATCH.control(INDEX,args)['owner'])

    def test_stop_drains_owned_child_without_termination_or_second_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            args=self.watch_args(temporary);folder=Path(temporary)/'watch';ticks=[0];children=[];commands=[]
            class Child:
                pid=4242;returncode=0
                def __init__(self):self.polls=0
                def poll(self):self.polls+=1;return None if self.polls<3 else 0
                def wait(self,timeout=None):return 0
            def launch(command,**kwargs):
                path=Path(command[command.index('--result')+1]);path.write_bytes(AUTO.canonical(dict(state='needs_review')))
                children.append(Child());return children[-1]
            auto=SimpleNamespace(select_baseline=lambda *_:(None,dict(files=[])),
                inventory=lambda *_:{'file':'same'},fingerprint=AUTO.fingerprint)
            def extension(name):return auto if name=='update-auto' else INDEX.extension(name)
            fake_index=SimpleNamespace(**{**vars(INDEX),'extension':extension})
            def queued(*_):
                if children and not commands:commands.append('stop');return ['stop']
                return []
            def sleep(seconds):ticks[0]+=60
            with patch.object(WATCH,'folder_for',return_value=folder),patch.object(WATCH,'process_creation',return_value='same'),\
                    patch.object(WATCH,'queued_commands',side_effect=queued),patch.object(WATCH,'definition_hint',return_value='defs'):
                # save_state needs canonical as well as the inventory adapter.
                auto.canonical=AUTO.canonical
                state=WATCH.watch(fake_index,args,clock=lambda:ticks[0],sleep=sleep,launcher=launch)
            self.assertEqual(state['state'],'stopped');self.assertEqual(len(children),1)
            self.assertEqual(state['last_result']['state'],'needs_review')
            self.assertIsNone(state['child'])

    def test_restart_does_not_repeat_unchanged_needs_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            args=self.watch_args(temporary);folder=Path(temporary)/'watch';ticks=[0]
            hint=AUTO.fingerprint({'file':'same'})
            WATCH.save_state(INDEX,folder,dict(state='stopped',owner=None,child=None,
                attempted_identity=hint,attempted_definitions='defs',last_result=dict(state='needs_review')))
            auto=SimpleNamespace(select_baseline=lambda *_:(None,dict(files=[])),inventory=lambda *_:{'file':'same'},
                fingerprint=AUTO.fingerprint,canonical=AUTO.canonical)
            fake=SimpleNamespace(**{**vars(INDEX),'extension':lambda name:auto if name=='update-auto' else INDEX.extension(name)})
            def sleep(seconds):ticks[0]+=60
            with patch.object(WATCH,'folder_for',return_value=folder),patch.object(WATCH,'process_creation',return_value='same'),\
                    patch.object(WATCH,'definition_hint',return_value='defs'):
                launcher=unittest.mock.Mock(side_effect=AssertionError('Unchanged run repeated'))
                state=WATCH.watch(fake,args,clock=lambda:ticks[0],sleep=sleep,launcher=launcher,stop_after=240)
            launcher.assert_not_called();self.assertEqual(state['state'],'stopped')


if __name__=='__main__':unittest.main()
