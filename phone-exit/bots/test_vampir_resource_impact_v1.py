"""Post-barrier resource observations never grant execution or runtime reuse."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from test_vampir_update_contracts import load
import test_vampir_resource_named_tables_v1 as named
import test_vampir_resource_pipeline_v3 as pipeline

IMPACT=load('resource-impact-v1')


class ResourceImpactTests(named.NamedTableScopeTests):
    def begin(self):
        super().begin()
        self.args.resource_named_tables_v1_scope=self.scope

    def setUp(self):
        super().setUp()
        self.audit_before='a'*64
        self.registry=dict(schema=1,contracts=[
            dict(id='tables',depends_on=[],resources=[dict(archive='*.pak',path='*.csv')]),
            dict(id='quests',depends_on=['tables'],resources=[dict(archive='*.pak',path='*Quest*')]),
            dict(id='native',depends_on=['quests'],resources=[])])
        self.save_registry()
        (self.knowledge/'resource-impact-engine.json').write_bytes(named.WORKFLOW.canonical(IMPACT.RULE))

    def save_registry(self):
        (self.knowledge/'update-contracts.json').write_bytes(named.WORKFLOW.canonical(self.registry))

    def impact(self, outcome=None, *, current=True):
        source=dict(sha256=named.digest(self.archive),size=self.archive.stat().st_size) if current else None
        self.row=dict(path=str(self.archive),current=source,baseline=dict(sha256=self.audit_before))
        report=dict(exe=dict(sha256='e'*64),files=[self.row])
        audit=self.snapshot('release-snapshots',report)
        scope=IMPACT.Scope(self.index,self.args,audit['path'],report)
        if outcome is not None:scope.observe(self.row,dict(named_tables=outcome))
        return scope

    def body(self, pointer):
        return json.loads(Path(pointer['path']).read_bytes())

    def dependency(self, body, consumer='tables'):
        return next(c for c in body['consumers'] if c['id']==consumer)['resources'][0]

    def previous(self, value='previous'):
        return self.legacy_reference([self.table('CSV/Quest.csv',value)])

    def test_cache_assignment_and_receipt_wait_for_completed_owner(self):
        self.previous();result=self.process();scope=self.impact(result)
        analysis=scope.prepare()
        self.assertEqual(scope.metrics,dict(analyses=1,cache_hits=0))
        self.assertEqual(self.cache_files(),[])
        with self.assertRaises(ValueError):scope.publish({})
        barrier=self.owner.finish();published=scope.publish(barrier)
        receipt=json.loads(Path(published['report']).read_bytes())
        self.assertEqual(receipt['analysis'],analysis)
        self.assertEqual(receipt['owner_barrier']['sha256'],barrier['sha256'])
        self.assertIs(receipt['execution_reuse_allowed'],False)
        self.assertIs(receipt['affected_plan_changed'],False)
        self.assertIs(receipt['profile_activated'],False)
        with self.assertRaises(ValueError):scope.publish(barrier)

    def test_warm_analysis_reuse_has_a_new_fresh_owner_receipt(self):
        self.previous();outcome=self.process();scope=self.impact(outcome)
        first=scope.prepare();published=scope.publish(self.owner.finish())
        self.begin();again=self.impact(self.process());second=again.prepare()
        self.assertEqual(first,second)
        self.assertEqual(again.metrics,dict(analyses=0,cache_hits=1))
        receipt=again.publish(self.owner.finish())
        self.assertNotEqual(receipt['report'],published['report'])

    def test_exact_csv_pattern_reports_changes_without_authorizing_reuse(self):
        self.previous();scope=self.impact(self.process());body=self.body(scope.prepare())
        dep=self.dependency(body)
        self.assertEqual(dep['state'],'observed_changes')
        self.assertEqual(dep['matched_counts']['changed'],1)
        self.assertEqual(dep['review_reasons'],[])
        self.assertIs(dep['consumer_reference_verified'],False)
        self.assertIs(dep['execution_reuse_allowed'],False)
        self.assertEqual(body['consumers'][0]['review_reasons'],['saved_consumer_resource_inputs_not_verified'])
        self.assertNotIn('native',{c['id'] for c in body['consumers']})

    def test_broad_pattern_retains_non_table_coverage_gap(self):
        self.previous();scope=self.impact(self.process());dep=self.dependency(self.body(scope.prepare()),'quests')
        self.assertIn('named_tables_do_not_cover_resource_pattern',dep['review_reasons'])
        self.assertEqual(dep['state'],'observed_changes')

    def test_older_named_baseline_never_aliases_nearest_audit_baseline(self):
        self.previous();self.audit_before='b'*64
        scope=self.impact(self.process());dep=self.dependency(self.body(scope.prepare()))
        self.assertEqual(dep['comparison_before_sha256'],'a'*64)
        self.assertEqual(dep['audit_before_sha256'],'b'*64)
        self.assertIn('named_baseline_differs_from_audit',dep['review_reasons'])

    def test_complete_named_unchanged_still_does_not_prove_saved_consumer_inputs(self):
        self.previous('current');scope=self.impact(self.process());dep=self.dependency(self.body(scope.prepare()))
        self.assertEqual(dep['state'],'named_paths_unchanged')
        self.assertEqual(dep['matched_counts']['unchanged'],1)
        self.assertIs(dep['execution_reuse_allowed'],False)

    def test_matching_unknown_hash_remains_review(self):
        table=self.table('CSV/Quest.csv','old');table.update(sha256=None,file=None)
        self.legacy_reference([table]);scope=self.impact(self.process())
        dep=self.dependency(self.body(scope.prepare()))
        self.assertEqual(dep['state'],'requires_review')
        self.assertIn('matching_payload_hash_unknown',dep['review_reasons'])

    def test_unrelated_unknown_path_does_not_become_a_matching_hash_gap(self):
        table=self.table('CSV/Unrelated.csv','old');table.update(sha256=None,file=None)
        self.legacy_reference([table,self.table('CSV/Quest.csv','current')])
        self.registry['contracts'][0]['resources'][0]['path']='*Quest.csv';self.save_registry()
        scope=self.impact(self.process());dep=self.dependency(self.body(scope.prepare()))
        self.assertEqual(dep['state'],'named_paths_unchanged')
        self.assertNotIn('matching_payload_hash_unknown',dep['review_reasons'])

    def test_missing_named_reference_and_missing_archive_are_explicit(self):
        scope=self.impact(self.process());dep=self.dependency(self.body(scope.prepare()))
        self.assertIn('named_inventory_incomplete',dep['review_reasons'])
        self.begin();scope=self.impact(current=False)
        dep=self.dependency(self.body(scope.prepare()))
        self.assertEqual(dep['review_reasons'],['current_archive_missing'])

    def test_rejected_named_processing_preserves_conservative_diagnostics(self):
        scope=self.impact(dict(state='requires_review',reason='fixture unsupported layout'))
        dep=self.dependency(self.body(scope.prepare()))
        self.assertEqual(dep['review_reasons'],['named_comparison_missing'])
        self.assertIs(dep['execution_reuse_allowed'],False)

    def test_unchanged_archive_requires_fresh_full_source_hash(self):
        self.audit_before=named.digest(self.archive);scope=self.impact()
        dep=self.dependency(self.body(scope.prepare()))
        self.assertEqual(dep['state'],'archive_unchanged')
        self.archive.write_bytes(b'changed after analysis')
        with self.assertRaises(ValueError):self.owner.finish()
        with self.assertRaises(ValueError):scope.publish({})

    def test_changed_audit_registry_or_selector_blocks_publication(self):
        for field in ('audit','registry','selector'):
            with self.subTest(field=field):
                self.begin();scope=self.impact();scope.prepare()
                path=(Path(scope.audit['path']) if field=='audit' else self.knowledge/
                    ('update-contracts.json' if field=='registry' else 'resource-impact-engine.json'))
                raw=path.read_bytes();path.write_bytes(raw+b' ')
                with self.assertRaises(ValueError):self.owner.finish()
                path.write_bytes(raw)

    def test_named_pointer_damage_and_cross_owner_scope_are_rejected(self):
        self.previous();outcome=self.process();scope=self.impact(outcome)
        p=Path(outcome['report']['path']);raw=p.read_bytes();p.write_bytes(raw+b' ')
        with self.assertRaises(ValueError):scope.prepare()
        p.write_bytes(raw)
        self.begin();outcome=self.process();scope=self.impact(outcome)
        self.args.resource_named_tables_v1_scope.owner=object()
        with self.assertRaises(ValueError):scope.prepare()

    def test_ambiguous_observation_and_wrong_source_are_rejected(self):
        scope=self.impact(dict(state='requires_review'))
        with self.assertRaises(ValueError):scope.observe(self.row,dict(named_tables=dict(state='compared')))
        with self.assertRaises(ValueError):scope.observe(dict(self.row,baseline=None),{})

    def test_barrier_damage_other_epoch_and_double_preparation_are_rejected(self):
        scope=self.impact();scope.prepare()
        with self.assertRaises(ValueError):scope.prepare()
        with self.assertRaises(ValueError):scope.observe(self.row,{})
        barrier=self.owner.finish();p=Path(barrier['report']);raw=p.read_bytes()
        p.write_bytes(raw+b' ')
        with self.assertRaises(ValueError):scope.publish(barrier)
        p.write_bytes(raw)
        proof=json.loads(raw);proof['epoch']='different owner'
        other=self.snapshot('knowledge/resource-owner-barriers-v4',proof)
        with self.assertRaises(ValueError):scope.publish(dict(barrier,report=other['path'],sha256=other['sha256']))

    def test_duplicate_archive_slots_and_unknown_registry_shape_are_rejected(self):
        scope=self.impact();audit=self.body(scope.audit);audit['files'].append(copy.deepcopy(self.row))
        p=self.snapshot('release-snapshots',audit)
        with self.assertRaises(ValueError):IMPACT.Scope(self.index,self.args,p['path'],audit)
        self.registry['contracts'][0]['resources'][0]['extra']=True;self.save_registry()
        with self.assertRaises(ValueError):self.impact()

    def test_unmatched_archive_pattern_stays_visible(self):
        self.registry['contracts'][0]['resources']=[dict(archive='*/not-installed.pak',path='*.csv')]
        self.save_registry();scope=self.impact();consumer=self.body(scope.prepare())['consumers'][0]
        self.assertEqual(consumer['resources'],[])
        self.assertEqual(consumer['unmatched_patterns'],self.registry['contracts'][0]['resources'])

    def test_damaged_warm_analysis_is_rejected_instead_of_rebuilt(self):
        scope=self.impact();pointer=scope.prepare();scope.publish(self.owner.finish())
        Path(pointer['path']).write_bytes(Path(pointer['path']).read_bytes()+b' ')
        self.begin();again=self.impact()
        with self.assertRaises(ValueError):again.prepare()


class PipelineImpactTests(pipeline.ResourcePipelineV3):
    def test_update_journal_exposes_diagnostics_without_changing_admission(self):
        (self.args.knowledge/'update-engine.json').write_bytes((self.index.HERE/'knowledge/update-engine.json').read_bytes())
        receipt=self.snapshot('fixture-resource-impact',dict(execution_reuse_allowed=False))
        result_hook=SimpleNamespace(process=Mock(return_value=dict(state='passed')),
            finish=lambda:dict(impact=receipt))
        self.f.modules['resource-pipeline-v3']=SimpleNamespace(enabled=lambda *a:True,
            plan=lambda report,*a:report['files'],Pipeline=Mock(return_value=result_hook))
        result,_=self.f.run_fixture()
        record=json.loads(Path(result['run']).read_bytes())['payload']
        self.assertEqual(record['resource_impact'],receipt)
        self.assertEqual(result['metrics']['resource_pipeline']['impact'],receipt)
        self.assertIs(result['profile_activation'],False)

    def test_ordinary_pipeline_prepares_before_owner_and_publishes_after(self):
        self.enable_owner();(self.args.knowledge/'resource-impact-engine.json').write_text('{}')
        events=[]
        hook=Mock()
        hook.prepare.side_effect=lambda:events.append(('prepare',self.args.resource_owner.state))
        hook.publish.side_effect=lambda barrier:events.append(('publish',self.args.resource_owner.state)) or dict(report='fixture')
        original=self.index.extension
        self.index.extension=lambda n:Mock(enabled=lambda *a:True,Scope=lambda *a:hook) if n=='resource-impact-v1' else original(n)
        p=self.pipeline();outcome=p.process(self.row);finished=p.finish()
        hook.observe.assert_called_once_with(self.row,outcome)
        self.assertEqual(events,[('prepare','open'),('publish','completed')])
        self.assertEqual(finished['impact'],dict(report='fixture'))


def load_tests(loader,tests,pattern):
    suite=unittest.TestSuite()
    for cls in (ResourceImpactTests,PipelineImpactTests):
        suite.addTests(cls(n) for n in sorted(cls.__dict__) if n.startswith('test_'))
    return suite


if __name__=='__main__':unittest.main()
