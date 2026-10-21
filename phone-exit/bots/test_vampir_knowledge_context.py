import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import test_vampir_knowledge_index as fixture_module


class KnowledgeContextTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        path = Path(__file__).parent / 'resource-tools/vampir/knowledge-index.py'
        spec = importlib.util.spec_from_file_location('context_index_test',path)
        self.index = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.index)
        self.knowledge = self.root/'curated'
        self.knowledge.mkdir()
        self.index.KNOWLEDGE = self.knowledge
        fixture = fixture_module.KnowledgeIndexTests()
        fixture.tool = self.index
        self.sha1, code1 = fixture.source(self.root,1)
        self.sha2, code2 = fixture.source(self.root,2)
        fixture.export(self.root,'one',self.sha1,code1)
        fixture.export(self.root,'two',self.sha2,code2)
        (self.knowledge/'questions.json').write_text(json.dumps(dict(questions=[dict(id='fixture-question',
            question='Shared question text',evidence=[])])),encoding='utf-8')
        (self.knowledge/'function-roles.json').write_text(json.dumps(dict(source_sha256=self.sha1,
            roles={'0x140001000':dict(role='Scoped old role',limits='Not a new release proof')})),encoding='utf-8')
        (self.knowledge/'note.md').write_text('# Shared navigation\n',encoding='utf-8')
        self.db = self.root/'knowledge/search.sqlite3'

    def test_documents_questions_are_unscoped_but_legacy_roles_do_not_transfer(self):
        self.index.build(self.root,self.db)
        db = self.index.open_index(self.db)
        try:
            rows = self.index.query(db,'search','Shared navigation',self.sha2,10)
            self.assertEqual(rows[0]['applicability'],'unscoped_navigation_not_release_proof')
            self.assertTrue(self.index.query(db,'search','Shared question text',self.sha2,10))
            self.assertFalse(self.index.query(db,'search','Scoped old role',self.sha2,10))
            self.assertEqual(self.index.query(db,'search','Scoped old role',self.sha1,10)[0]['kind'],'role')
        finally: db.close()

    def test_supported_replay_keeps_limits_and_case_count_without_raw_cases(self):
        workflow = self.index.extension('research-workflow')
        base = self.root/'ghidra/release-comparisons/fixture/run-test'
        report = dict(source_sha256=self.sha2,tool_sha256='a'*64,
            cases=[dict(raw='Do not index case bodies')],limits=['Synthetic service fixture'],native_execution=True)
        path = workflow.snapshot(self.root,'temp',report)
        target = base/'fixture-replay'/path.parent.name/'manifest.json'
        target.parent.mkdir(parents=True)
        target.write_bytes(path.read_bytes())
        self.index.build(self.root,self.db)
        db = self.index.open_index(self.db)
        try:
            rows = self.index.query(db,'search','Synthetic service fixture',self.sha2,10)
            self.assertEqual(rows[0]['kind'],'native_replay')
            self.assertFalse(self.index.query(db,'search','Do not index case bodies',self.sha2,10))
        finally: db.close()
        before = self.db.read_bytes()
        target.write_text('{}',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'Replay manifest digest'):
            self.index.build(self.root,self.db)
        self.assertEqual(before,self.db.read_bytes())

    def test_unsupported_replay_is_inventory_without_perpetual_rebuild(self):
        workflow = self.index.extension('research-workflow')
        report = workflow.snapshot(self.root,'temp',dict(schema='unsupported'))
        target = self.root/'ghidra/release-comparisons/fixture/run-test/fixture-replay'/report.parent.name/'manifest.json'
        target.parent.mkdir(parents=True)
        target.write_bytes(report.read_bytes())
        self.index.build(self.root,self.db)
        self.assertTrue(self.index.build(self.root,self.db)['reused'])


if __name__ == '__main__': unittest.main()
