import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_vampir_knowledge_index as fixture_module


class ResearchUpdateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'resources'
        self.root.mkdir()
        path = Path(__file__).parent / 'resource-tools/vampir/knowledge-index.py'
        spec = importlib.util.spec_from_file_location('research_update_index', path)
        self.index = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.index)
        fixture = fixture_module.KnowledgeIndexTests()
        fixture.tool = self.index
        self.sha, _ = fixture.source(self.root, 1)
        self.workflow = self.index.extension('research-workflow')
        self.update = self.index.extension('research-update')
        self.knowledge = self.root / 'curated'
        self.knowledge.mkdir()
        self.index.KNOWLEDGE = self.knowledge
        (self.knowledge / 'questions.json').write_text(json.dumps(dict(questions=[dict(id='question')])), encoding='utf-8')
        self.install = self.root.parent / 'install'
        self.exe = self.install / 'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'
        self.exe.parent.mkdir(parents=True)
        self.exe.write_bytes((self.root / 'client-code-snapshots' / self.sha / self.exe.name).read_bytes())
        self.pak = self.install / 'ProjectRED/Content/Paks/example.pak'
        self.pak.parent.mkdir(parents=True)
        self.pak.write_bytes(b'fixture archive')
        audit = self.index.extension('audit-client-release')
        current = audit.inspect_archive(self.pak)
        current['sha256'] = self.index.digest(self.pak)
        baseline = dict(source=str(self.install), exe=dict(path=str(self.exe),sha256=self.sha),
            files=[dict(path=str(self.pak),current=current,status='changed')])
        manifest = self.workflow.snapshot(self.root,'fixture-baselines',baseline)
        self.args = SimpleNamespace(root=self.root,knowledge=self.knowledge,install=self.install,
            baseline=manifest,audit_only=False)

    def test_unchanged_release_does_not_extract_or_promote_baseline(self):
        with patch.object(self.update,'execute_adapter',side_effect=AssertionError('Must reuse')):
            result = self.update.update(self.index.api(),self.args,self.root/'knowledge/search.sqlite3')
        self.assertFalse(result['changed_exe'])
        self.assertEqual(result['resource_steps'],0)
        self.assertFalse(result['baseline_promoted'])

    def test_middle_content_change_with_preserved_stat_is_found_by_full_hash(self):
        old = self.pak.stat()
        self.pak.write_bytes(b'fixture ARCHIVE')
        import os
        os.utime(self.pak, ns=(old.st_atime_ns,old.st_mtime_ns))
        self.args.audit_only = True
        result = self.update.update(self.index.api(),self.args,self.root/'knowledge/search.sqlite3')
        report = self.workflow.checked_manifest(self.index.api(),Path(result['report']))
        self.assertEqual(report['comparison']['counts']['content_changed'],1)
        self.assertGreater(result['queue'],0)

    def test_changed_inventory_aborts_without_source_snapshot_promotion(self):
        before = self.update.signatures(self.install)
        with patch.object(self.update,'signatures',side_effect=[before,{}]):
            with self.assertRaisesRegex(ValueError,'Installation changed'):
                self.update.audit_install(self.index.api(),self.workflow,self.args)

    def test_unknown_resource_format_becomes_manual_queue(self):
        self.pak.write_bytes(b'new unknown format')
        with patch.object(self.update,'execute_adapter',side_effect=AssertionError('No parser for unknown format')):
            result = self.update.update(self.index.api(),self.args,self.root/'knowledge/search.sqlite3')
        self.assertEqual(result['resource_steps'],0)
        self.assertGreater(result['queue'],0)

    def test_baseline_archives_outside_game_pak_roots_are_not_reported_removed(self):
        extra = self.install/'Engine/Binaries/ThirdParty/CEF3/Resources/resources.pak'
        extra.parent.mkdir(parents=True)
        extra.write_bytes(b'browser fixture')
        baseline = self.workflow.checked_manifest(self.index.api(),self.args.baseline)
        current = self.index.extension('audit-client-release').inspect_archive(extra)
        current['sha256'] = self.index.digest(extra)
        baseline['files'].append(dict(path=str(extra),current=current))
        self.args.baseline = self.workflow.snapshot(self.root,'fixture-baselines',baseline)
        result = self.update.update(self.index.api(),self.args,self.root/'knowledge/search.sqlite3')
        report = self.workflow.checked_manifest(self.index.api(),Path(result['report']))
        self.assertEqual(report['comparison']['counts'],{'full_hash_equal':2})

    def test_changed_supported_archive_runs_existing_adapters(self):
        import struct
        self.pak.write_bytes(b'fixture PAK' + struct.pack('<Ii',0x5a6f12e1,11) + bytes(8))
        for path in (self.root/'table-study/index.json', self.root/'pak-extracted/example/entries.json'):
            path.parent.mkdir(parents=True)
            path.write_text('[]',encoding='utf-8')
        calls = []
        def adapter(index,args,tool,arguments):
            calls.append(tool)
            if tool == 'index-release-archives.py':
                manifest = Path(arguments[0])
                record = self.workflow.snapshot(self.root,'fixture-records',dict(schema=1))
                summary = dict(selected_archive_sha256=arguments[2],archives=[dict(report=str(record))])
                raw = self.workflow.canonical(summary)
                import hashlib
                target = manifest.parent/'index-summaries'/hashlib.sha256(raw).hexdigest()/'manifest.json'
                target.parent.mkdir(parents=True)
                target.write_bytes(raw)
            return dict(tool=tool,state='passed',result={})
        with patch.object(self.update,'execute_adapter',side_effect=adapter):
            result = self.update.update(self.index.api(),self.args,self.root/'knowledge/search.sqlite3')
        self.assertEqual(calls,['index-release-archives.py','compare-release-assets.py','extract-release-tables.py'])
        self.assertEqual(result['resource_steps'],3)

    def test_new_exe_creates_separate_snapshot_and_review_queue(self):
        raw = bytearray(self.exe.read_bytes())
        raw[0x201] = 2
        self.exe.write_bytes(raw)
        with patch.object(self.update, 'execute_adapter', return_value=dict(state='passed', result={})) as adapter:
            result = self.update.update(self.index.api(),self.args,self.root/'knowledge/search.sqlite3')
        self.assertEqual(adapter.call_args.args[2], 'locate-release-update-targets.py')
        self.assertTrue(result['changed_exe'])
        self.assertNotEqual(result['source_sha256'],self.sha)
        self.assertEqual(result['queue'],1)
        self.assertTrue((self.root/'client-code-snapshots'/self.sha/self.exe.name).is_file())

    def test_failed_native_discovery_stays_in_queue_without_promoting_profile(self):
        raw = bytearray(self.exe.read_bytes()); raw[0x201] = 3
        self.exe.write_bytes(raw)
        with patch.object(self.update, 'execute_adapter', return_value=dict(state='failed', result=None)):
            result = self.update.update(self.index.api(), self.args, self.root/'knowledge/search.sqlite3')
        report = self.workflow.checked_manifest(self.index.api(), Path(result['report']))
        self.assertEqual(report['native_targets']['state'], 'failed')
        self.assertTrue(any('Native target discovery failed' in task['reason'] for task in report['queue']))
        self.assertEqual(report['compatibility'], 'not_established')
        self.assertFalse(report['baseline_promoted'])

    def test_audit_only_new_exe_does_not_run_candidate_discovery(self):
        raw = bytearray(self.exe.read_bytes()); raw[0x201] = 4
        self.exe.write_bytes(raw); self.args.audit_only = True
        with patch.object(self.update, 'execute_adapter', side_effect=AssertionError('Audit only')):
            result = self.update.update(self.index.api(), self.args, self.root/'knowledge/search.sqlite3')
        report = self.workflow.checked_manifest(self.index.api(), Path(result['report']))
        self.assertIsNone(report['native_targets'])

    def test_additional_target_plan_runs_sequentially_and_ambiguity_stays_queued(self):
        primary = self.knowledge/'release-update-targets.json'
        primary.write_text(json.dumps(dict(additional_target_plans=['gmc.json'])), 'utf-8')
        (self.knowledge/'gmc.json').write_text('{}', 'utf-8')
        raw = bytearray(self.exe.read_bytes()); raw[0x201] = 5
        self.exe.write_bytes(raw)
        calls = []
        def adapter(index, args, tool, arguments):
            plan = Path(arguments[-1]).name
            calls.append(plan)
            return dict(state='passed', result=dict(candidates=[dict(state='candidate' if len(calls)==1 else 'requires_review')]))
        with patch.object(self.update, 'execute_adapter', side_effect=adapter):
            result = self.update.update(self.index.api(), self.args, self.root/'knowledge/search.sqlite3')
        report = self.workflow.checked_manifest(self.index.api(), Path(result['report']))
        self.assertEqual(calls, ['release-update-targets.json', 'gmc.json'])
        self.assertEqual(report['additional_native_targets'][0]['plan'], 'gmc.json')
        self.assertTrue(any(task.get('plan') == 'gmc.json' for task in report['queue']))
        self.assertFalse(report['baseline_promoted'])
        self.assertEqual(report['compatibility'], 'not_established')

    def test_additional_target_plan_cannot_escape_scope_or_expand_without_bound(self):
        primary = self.knowledge/'release-update-targets.json'
        for names in (['../outside.json'], ['missing.json'], ['a.json']*2,
                      ['a.json','b.json','c.json','d.json'], [{}]):
            with self.subTest(names=names):
                primary.write_text(json.dumps(dict(additional_target_plans=names)), 'utf-8')
                with self.assertRaises(ValueError):
                    self.update.target_plans(self.index.api(), self.knowledge)

    def register_update_checks(self, checks):
        (self.knowledge/'research-checks.json').write_text(json.dumps(dict(schema=1, checks=checks)), 'utf-8')

    def test_update_runs_only_opted_in_checks_and_queues_nonpassing_results(self):
        self.register_update_checks([dict(id='current', on_update=True, offline_reviewed=True),
            dict(id='unported', on_update=True, offline_reviewed=True),
            dict(id='failed', on_update=True, offline_reviewed=True), dict(id='unrelated')])
        calls = []
        def run(index, args, sha, question, *, check_ids):
            calls.append(check_ids)
            name = check_ids[0]
            return [dict(id=name, state=dict(current='passed', unported='requires_port', failed='failed')[name])]
        with patch.object(self.workflow, 'run_checks', side_effect=run):
            checked = self.update.run_update_checks(self.index.api(), self.workflow, self.args, self.sha)
        with patch.object(self.update, 'run_update_checks', return_value=checked):
            result = self.update.update(self.index.api(), self.args, self.root/'knowledge/search.sqlite3')
        report = self.workflow.checked_manifest(self.index.api(), Path(result['report']))
        self.assertEqual(calls, [['current'], ['unported'], ['failed']])
        self.assertEqual([r['check'] for r in report['queue']], ['unported', 'failed'])
        self.assertEqual(len(report['checks']), 3)
        self.assertFalse(report['baseline_promoted'])

    def test_update_input_error_and_unreviewed_check_stay_in_queue(self):
        self.register_update_checks([dict(id='corrupt', on_update=True, offline_reviewed=True),
            dict(id='unreviewed', on_update=True, offline_reviewed=False)])
        with patch.object(self.workflow, 'run_checks', side_effect=ValueError('fixture dependency changed')) as run:
            checked = self.update.run_update_checks(self.index.api(), self.workflow, self.args, self.sha)
        with patch.object(self.update, 'run_update_checks', return_value=checked):
            result = self.update.update(self.index.api(), self.args, self.root/'knowledge/search.sqlite3')
        report = self.workflow.checked_manifest(self.index.api(), Path(result['report']))
        run.assert_called_once()
        self.assertEqual([c['state'] for c in report['checks']], ['requires_review', 'requires_review'])
        self.assertEqual(len(report['queue']), 2)

    def test_audit_only_skips_opted_in_checks(self):
        self.register_update_checks([dict(id='current', on_update=True, offline_reviewed=True)])
        self.args.audit_only = True
        with patch.object(self.update, 'run_update_checks', side_effect=AssertionError('Audit only')):
            result = self.update.update(self.index.api(), self.args, self.root/'knowledge/search.sqlite3')
        report = self.workflow.checked_manifest(self.index.api(), Path(result['report']))
        self.assertEqual(report['checks'], [])

    def test_update_checks_share_dependency_cache_and_new_source_requires_port(self):
        # Use a reviewed synthetic unittest already present in the workspace;
        # subprocess itself is mocked, so no nested update/auth work is executed.
        test = 'test_vampir_research_update.py'
        self.register_update_checks([dict(id='fixture', on_update=True, offline_reviewed=True,
            questions=['question'], source_sha256=[self.sha], test_pattern=test, dependencies=[])])
        from types import SimpleNamespace
        with patch.object(self.workflow.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run:
            first = self.update.run_update_checks(self.index.api(), self.workflow, self.args, self.sha)
            second = self.update.run_update_checks(self.index.api(), self.workflow, self.args, self.sha)
            other = self.update.run_update_checks(self.index.api(), self.workflow, self.args, 'f'*64)
        run.assert_called_once()
        self.assertEqual(first, second)
        self.assertEqual(other[0]['state'], 'requires_port')


if __name__ == '__main__': unittest.main()
