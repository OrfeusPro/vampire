import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_vampir_knowledge_index as fixture_module


class ResearchWorkflowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        path = Path(__file__).parent / 'resource-tools/vampir/knowledge-index.py'
        spec = importlib.util.spec_from_file_location('research_index_test', path)
        self.index = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.index)
        self.knowledge = self.root / 'curated'
        self.knowledge.mkdir()
        self.index.KNOWLEDGE = self.knowledge
        self.workflow = self.index.extension('research-workflow')
        self.fixture = fixture_module.KnowledgeIndexTests()
        self.fixture.tool = self.index
        self.sha, code = self.fixture.source(self.root, 1)
        self.export = self.fixture.export(self.root, 'complete', self.sha, code)
        self.db = self.root / 'knowledge/search.sqlite3'
        self.questions = self.knowledge / 'questions.json'
        self.questions.write_text(json.dumps(dict(questions=[dict(id='test-question',
            question='Fixture research', next_action='Inspect a concrete unknown', evidence=[])])), encoding='utf-8')
        self.args = SimpleNamespace(root=self.root, knowledge=self.knowledge, release=self.sha,
            question='test-question', function=['140001000'], reason=None)

    def prepare(self):
        result = self.workflow.prepare(self.index.api(), self.args, self.db)
        self.args.request = Path(result['request'])
        return result

    def result(self):
        proof = self.knowledge / 'proof.md'
        proof.write_text('# Synthetic result\n\nExplicit limits.\n', encoding='utf-8')
        self.args.result = self.root / 'result.json'
        value = dict(question='test-question', source_sha256=self.sha, addresses=['140001000'],
            conclusion='Verified fixture behavior', method='static', limits=['Synthetic inputs only'],
            unknown='Full lifecycle remains unknown', next_check='Inspect the next caller',
            evidence=[dict(path=str(proof), sha256=self.index.digest(proof))])
        self.args.result.write_text(json.dumps(value), encoding='utf-8')
        return value

    def test_preparation_is_repeatable_and_ready_export_does_not_start_ghidra(self):
        first = self.prepare()
        second = self.prepare()
        self.assertEqual(first['request'], second['request'])
        with patch.object(self.workflow, 'collector', side_effect=AssertionError('Ghidra must not run')):
            collected = self.workflow.collect(self.index.api(), self.args, self.db)
        self.assertEqual(collected['state'], 'reused')

    def test_incomplete_result_lists_missing_fields_and_does_not_change_database(self):
        self.prepare()
        before = self.db.read_bytes()
        self.args.result = self.root / 'result.json'
        self.args.result.write_text('{}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'conclusion.*limits.*unknown.*next_check.*evidence'):
            self.workflow.finish(self.index.api(), self.args, self.db)
        self.assertEqual(before, self.db.read_bytes())
        self.assertFalse((self.knowledge / 'releases').exists())

    def test_finish_deduplicates_scoped_facts_and_refreshes_only_context(self):
        self.prepare()
        self.result()
        first = self.workflow.finish(self.index.api(), self.args, self.db)
        second = self.workflow.finish(self.index.api(), self.args, self.db)
        self.assertEqual(first['fact_id'], second['fact_id'])
        facts = json.loads(Path(first['facts']).read_text('utf-8'))
        self.assertEqual(len(facts['facts']), 1)
        db = self.index.open_index(self.db)
        try:
            result = self.index.query(db, 'search', 'Verified fixture behavior', self.sha, 5)
            self.assertEqual(result[0]['kind'], 'fact')
            self.assertEqual(result[0]['source_sha'], self.sha)
        finally: db.close()
        (self.knowledge / 'unrelated.md').write_text('# Other note\n', encoding='utf-8')
        refreshed = self.index.build(self.root, self.db, knowledge=self.knowledge)
        self.assertTrue(refreshed['code_reused'])

    def test_changed_exe_and_tampered_request_are_rejected(self):
        self.prepare()
        self.result()
        request = self.index.read_json(self.args.request)
        request['require_installed_match'] = True
        request_path = self.workflow.snapshot(self.root, 'requests', request)
        self.args.request = request_path
        with patch.object(self.index, 'INSTALL', self.questions):
            with self.assertRaisesRegex(ValueError, 'Installed client changed'):
                self.workflow.finish(self.index.api(), self.args, self.db)
        request_path.write_text('{}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'manifest digest'):
            self.workflow.collect(self.index.api(), self.args, self.db)

    def test_failed_collection_is_not_automatically_retried(self):
        self.args.function = ['140001020']
        self.prepare()
        with patch.object(self.workflow, 'collector', side_effect=ValueError('Synthetic failure')) as collect:
            with self.assertRaisesRegex(ValueError, 'Synthetic failure'):
                self.workflow.collect(self.index.api(), self.args, self.db)
            result = self.workflow.collect(self.index.api(), self.args, self.db)
            self.assertEqual(collect.call_count, 1)
            self.assertEqual(result['state'], 'queued')

    def test_collection_success_imports_only_explicit_missing_address(self):
        self.args.function = ['140001020']
        self.prepare()
        def collect(index, args, request, addresses):
            self.assertEqual(addresses, ['0x140001020'])
            # Simulate the existing export adapter, then require normal receipt
            # and source byte validation before its result is reused.
            report = self.fixture.export(self.root, 'new-export', self.sha, b'\0')
            data = json.loads(report.read_text())
            data['functions'][0]['address'] = '0x140001020'
            data['functions'][0]['instructions'] = [dict(address='0x140001020',bytes='00',text='fixture')]
            report.write_text(json.dumps(data),encoding='utf-8')
            receipt = report.parent / 'provenance.json'
            provenance = json.loads(receipt.read_text())
            provenance['files']['details.json'] = index.digest(report)
            receipt.write_text(json.dumps(provenance),encoding='utf-8')
            return dict(state='collected',addresses=addresses,queue=[])
        with patch.object(self.workflow,'collector',side_effect=collect) as run:
            self.assertEqual(self.workflow.collect(self.index.api(),self.args,self.db)['state'],'collected')
            self.assertEqual(self.workflow.collect(self.index.api(),self.args,self.db)['state'],'reused')
            self.assertEqual(run.call_count,1)

    def test_failed_check_prevents_finish_and_preserves_fact_store(self):
        self.prepare()
        self.result()
        with patch.object(self.workflow,'run_checks',return_value=[dict(id='failed',state='failed')]):
            with self.assertRaisesRegex(ValueError,'Required checks'):
                self.workflow.finish(self.index.api(),self.args,self.db)
        self.assertFalse((self.knowledge/'releases').exists())

    def test_check_cache_tracks_only_declared_dependencies(self):
        registry = dict(schema=1, checks=[dict(id='offline-fixture', questions=['test-question'],
            source_sha256=[self.sha], offline_reviewed=True,
            test_pattern='test_vampir_research_workflow.py', dependencies=[], timeout_seconds=10)])
        path = self.knowledge / 'research-checks.json'
        path.write_text(json.dumps(registry), encoding='utf-8')
        with patch.object(self.workflow.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run:
            first = self.prepare()
            (self.knowledge / 'unrelated.md').write_text('# Unrelated\n', encoding='utf-8')
            second = self.prepare()
            self.assertEqual(run.call_count, 1)
            self.assertEqual(first['checks'], second['checks'])
            registry['checks'][0]['dependencies'] = ['phone-exit/bots/resource-tools/vampir/knowledge-index.py']
            path.write_text(json.dumps(registry), encoding='utf-8')
            third = self.prepare()
            self.assertEqual(run.call_count, 2)
            self.assertNotEqual(second['checks'][0]['cache_key'], third['checks'][0]['cache_key'])

    def test_actual_dependency_content_change_invalidates_selected_check(self):
        workspace = self.root / 'workspace'
        fake_here = workspace / 'phone-exit/bots/resource-tools/vampir'
        fake_here.mkdir(parents=True)
        test = workspace / 'phone-exit/bots/test_vampir_fixture.py'
        test.write_text('# synthetic offline test\n',encoding='utf-8')
        dependency = workspace / 'dependency.py'
        dependency.write_text('value = 1\n',encoding='utf-8')
        definition = dict(schema=1,checks=[dict(id='fixture',questions=['test-question'],
            source_sha256=[self.sha],offline_reviewed=True,test_pattern='test_vampir_fixture.py',
            dependencies=['dependency.py'])])
        (self.knowledge/'research-checks.json').write_text(json.dumps(definition),encoding='utf-8')
        api = self.index.api()
        api.HERE = fake_here
        with patch.object(self.workflow.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as run:
            first = self.workflow.run_checks(api,self.args,self.sha,'test-question')
            dependency.write_text('value = 2\n',encoding='utf-8')
            second = self.workflow.run_checks(api,self.args,self.sha,'test-question')
            self.assertEqual(run.call_count,2)
            self.assertNotEqual(first[0]['cache_key'],second[0]['cache_key'])


if __name__ == '__main__': unittest.main()
