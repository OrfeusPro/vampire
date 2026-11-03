"""Scoped workflow integration, rollback and admission tests; no native or JVM."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_update_contracts import load
import test_vampir_knowledge_scope_v2 as scope_fixtures

write_json = scope_fixtures.write_json

WORK = load('research-scoped-v2')
LEGACY = load('research-workflow')


class ScopedResearchWorkflow(unittest.TestCase):
    def setUp(self):
        self.fixture = f = scope_fixtures.KnowledgeScopeV2()
        f.setUp(); self.addCleanup(f.doCleanups)
        write_json(f.knowledge/'research-checks.json', dict(schema=1, checks=[]))
        real = load('knowledge-index').api()
        real.INSTALL = f.source
        extension = real.extension
        self.collector = Mock(return_value=dict(state='collected', addresses=[f.first], queue=[], export=str(f.report)))
        self.check_runner = Mock(return_value=[])
        self.workflow = SimpleNamespace(atomic=LEGACY.atomic, snapshot=LEGACY.snapshot,
            locked=LEGACY.locked, run_checks=self.check_runner, collector=self.collector)
        real.extension = lambda name:self.workflow if name=='research-workflow' else extension(name)
        real.build = Mock(side_effect=AssertionError('A global index build must not run'))
        self.index = real
        self.args = SimpleNamespace(root=f.root, knowledge=f.knowledge, release='installed',
            question='q', function=[f.first], reason='Fixture workflow', export=[f.report], context=[])
        self.database = f.root/'missing.sqlite3'

    def prepare(self):
        value = WORK.prepare(self.index, self.args, self.database)
        self.args.request = Path(value['request'])
        return value

    def finish(self):
        f = self.fixture
        evidence = f.knowledge/'result.md';evidence.write_text('Выбранный fixture проверен.', encoding='utf-8')
        result = dict(question='q', source_sha256=f.source_sha, addresses=[f.first],
            method='static', conclusion='Selected fixture only', limits=['No client semantics'],
            unknown='Online unknown', next_check='No game action',
            evidence=[WORK.pointer(self.index,evidence)])
        self.args.result = f.root/'result.json';write_json(self.args.result,result)
        value=WORK.finish(self.index,self.args,self.database)
        self.args.completion=Path(value['report'])
        return value

    def test_ready_explicit_export_survives_missing_db_and_collect_never_launches(self):
        value=self.prepare()
        self.assertEqual(value['functions'][0]['state'],'ready')
        again=self.prepare();self.assertEqual(value['sha256'],again['sha256'])
        collected=WORK.collect(self.index,self.args,self.database)
        self.assertEqual(collected['state'],'reused');self.collector.assert_not_called()
        self.assertFalse(collected['global_history_verified']);self.index.build.assert_not_called()

    def test_successful_missing_collection_is_reused_without_discovery_db_write(self):
        self.args.export=[];self.prepare()
        first=WORK.collect(self.index,self.args,self.database)
        self.assertEqual(first['state'],'collected')
        second=WORK.collect(self.index,self.args,self.database)
        self.assertEqual(second['state'],'reused');self.collector.assert_called_once()
        self.assertFalse(self.database.exists())

    def test_failed_collection_does_not_loop_on_same_request(self):
        self.args.export=[];self.prepare();self.collector.side_effect=ValueError('fixture failure')
        with self.assertRaisesRegex(ValueError,'fixture failure'):
            WORK.collect(self.index,self.args,self.database)
        value=WORK.collect(self.index,self.args,self.database)
        self.assertEqual(value['state'],'queued');self.collector.assert_called_once()

    def test_finish_preserves_old_fact_objects_and_is_idempotent(self):
        self.prepare();f=self.fixture
        target=f.knowledge/'releases'/f.source_sha/'facts.json'
        old=dict(id='d'*64, old_historical_field='not reinterpreted')
        write_json(target,dict(schema=1,source_sha256=f.source_sha,facts=[old]))
        value=self.finish();before=target.read_bytes()
        again=WORK.finish(self.index,self.args,self.database)
        self.assertEqual(value['fact_id'],again['fact_id']);self.assertEqual(target.read_bytes(),before)
        data=json.loads(before);self.assertEqual(data['facts'][0],old);self.assertEqual(len(data['facts']),2)
        checked=WORK.check(self.index,self.args,self.database)
        self.assertEqual(checked['state'],'passed');self.assertFalse(checked['global_history_verified'])

    def test_question_output_update_allowed_but_decision_rule_change_rejected(self):
        self.prepare();f=self.fixture
        questions=json.loads((f.knowledge/'questions.json').read_bytes())
        questions['questions'][0].update(known='New result',evidence=['result.md'],next_action='Next')
        write_json(f.knowledge/'questions.json',questions)
        self.assertEqual(WORK.load_request(self.index,self.args)['question'],'q')
        questions['questions'][0]['decision_rule']='Changed admission rule'
        write_json(f.knowledge/'questions.json',questions)
        with self.assertRaisesRegex(ValueError,'вопрос изменился'):
            WORK.load_request(self.index,self.args)

    def test_completion_checks_current_mandatory_checks_not_only_old_hashes(self):
        self.prepare();self.finish()
        with patch.object(WORK,'run_checks',return_value=[dict(id='new-required',state='passed')]):
            with self.assertRaisesRegex(ValueError,'проверки или runtime'):
                WORK.check(self.index,self.args,self.database)

    def test_native_fact_cannot_be_proved_by_tooling_or_no_checks(self):
        self.prepare();self.finish()
        value=json.loads(self.args.result.read_bytes());value['method']='bounded_native'
        write_json(self.args.result,value)
        with self.assertRaisesRegex(ValueError,'source-bound client check'):
            WORK.finish(self.index,self.args,self.database)

    def test_evidence_and_result_address_scope_are_checked(self):
        self.prepare();self.finish();value=json.loads(self.args.result.read_bytes())
        value['addresses']=[self.fixture.second];write_json(self.args.result,value)
        with self.assertRaisesRegex(ValueError,'расширяет адреса'):
            WORK.finish(self.index,self.args,self.database)
        value['addresses']=[self.fixture.first]
        value['evidence'][0]['path']=str(self.fixture.root/'captures/secret.json')
        write_json(self.args.result,value)
        with self.assertRaisesRegex(ValueError,'вне knowledge'):
            WORK.finish(self.index,self.args,self.database)

    def test_fact_rollback_on_post_write_source_barrier_failure(self):
        self.prepare();self.finish();f=self.fixture
        target=f.knowledge/'releases'/f.source_sha/'facts.json';before=target.read_bytes()
        result=json.loads(self.args.result.read_bytes());result['conclusion']='Another fixture result'
        write_json(self.args.result,result)
        original=WORK.verify_installed;calls=[]
        def fail_after(index,required,sha):
            calls.append(True)
            if len(calls)==3:raise ValueError('post-write source changed')
            return original(index,required,sha)
        with patch.object(WORK,'verify_installed',side_effect=fail_after):
            with self.assertRaisesRegex(ValueError,'post-write'):
                WORK.finish(self.index,self.args,self.database)
        self.assertEqual(target.read_bytes(),before)


if __name__=='__main__':unittest.main()
