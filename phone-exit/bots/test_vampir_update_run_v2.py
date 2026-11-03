"""Checked selected database bridge, missing-only collection and final barriers."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_update_contracts import load
import test_vampir_knowledge_scope_v2 as scope_fixtures
import test_vampir_update_run as engine_fixtures

V2, ENGINE, WORKFLOW = (load(name) for name in ('update-run-v2','update-run','research-workflow'))


class ScopedNativeUpdate(unittest.TestCase):
    def setUp(self):
        f=scope_fixtures.KnowledgeScopeV2();f.setUp();self.addCleanup(f.doCleanups);self.f=f
        self.index=load('knowledge-index').api()
        self.index.build=Mock(side_effect=AssertionError('Global build is forbidden'))
        self.index.INSTALL=f.source
        store=load('update-bindings').SourceStore(self.index,f.root)
        self.args=SimpleNamespace(root=f.root,knowledge=f.knowledge,source_store=store)
        self.contexts=dict(source_sha256=f.source_sha,contracts={'fixture':dict(bindings={'entry':f.first})})
        self.database=f.discovery_db(body='forged payload',completed=0)
        self.actions=[]
        self.journal=SimpleNamespace(run={'stages':{}},stage=self.stage)

    def stage(self,name,inputs,action):
        self.actions.append(name)
        return action()

    def collect(self,database=None):
        return V2.collect_batches(self.index,WORKFLOW,self.journal,self.args,
            database or self.database,self.contexts,self.f.source_sha)

    def test_only_checked_rows_enter_distinct_database_with_no_global_writer(self):
        before=self.database.read_bytes();rows=self.collect()
        self.assertEqual(rows[0]['state'],'ready');self.assertEqual(self.actions,[])
        self.assertNotEqual(self.args.scoped_database,self.database)
        db=self.index.open_index(self.args.scoped_database)
        try:
            state=WORKFLOW.function_state(self.index,db,self.f.source_sha,self.f.first)
            self.assertEqual(state['state'],'ready')
            body=json.loads(db.execute('SELECT body_json FROM variants').fetchone()[0])
            self.assertEqual(body['instructions'],self.f.rows[0]['instructions'])
        finally:db.close()
        self.assertEqual(self.database.read_bytes(),before);self.index.build.assert_not_called()
        final=V2.finish(self.index,self.args)
        self.assertFalse(final['global_history_verified']);self.assertEqual(final['selected_rows'],1)

    def test_source_pseudocode_and_selected_database_mutations_block_finalization(self):
        for target in ('source','pseudocode','database'):
            with self.subTest(target=target):
                self.setUp();self.collect()
                path={'source':self.f.source,'pseudocode':self.f.pseudo,'database':self.args.scoped_database}[target]
                path.write_bytes(path.read_bytes()+b'!')
                with self.assertRaises(ValueError):V2.finish(self.index,self.args)

    def test_missing_only_collector_and_validated_sidecar_resume_without_index_rebuild(self):
        extension=self.index.extension;collector=Mock(return_value=dict(state='collected',
            export=str(self.f.report),addresses=[self.f.first],queue=[]))
        workflow=SimpleNamespace(atomic=WORKFLOW.atomic,canonical=WORKFLOW.canonical,
            snapshot=WORKFLOW.snapshot,collector=collector)
        self.index.extension=lambda name:workflow if name=='research-workflow' else extension(name)
        # The standard collector is provided explicitly; no global index exists.
        self.database=self.f.root/'absent.sqlite3'
        rows=V2.collect_batches(self.index,workflow,self.journal,self.args,self.database,self.contexts,self.f.source_sha)
        collector.assert_called_once();self.assertEqual(rows[-1]['state'],'ready')
        args=SimpleNamespace(root=self.f.root,knowledge=self.f.knowledge,
            source_store=load('update-bindings').SourceStore(self.index,self.f.root))
        no_actions=SimpleNamespace(run={'stages':{}},stage=Mock(side_effect=AssertionError('Repeated JVM')))
        again=V2.collect_batches(self.index,workflow,no_actions,args,self.database,self.contexts,self.f.source_sha)
        self.assertEqual(again[0]['state'],'ready');collector.assert_called_once()

    def test_recipe_is_explicit_and_unknown_settings_fail_closed(self):
        self.assertFalse(V2.enabled(self.index,self.args))
        scope_fixtures.write_json(self.f.knowledge/'update-engine.json',dict(schema=2,recipe='unknown'))
        with self.assertRaisesRegex(ValueError,'Неизвестный recipe'):V2.enabled(self.index,self.args)
        real=V2.HERE/'knowledge/update-engine.json'
        (self.f.knowledge/'update-engine.json').write_bytes(real.read_bytes())
        self.assertTrue(V2.enabled(self.index,self.args))

    def test_publication_recipe_is_machine_selected_and_unknown_recipe_rejected(self):
        self.assertEqual(V2.publication_driver(self.index,self.args),'update-native-drivers-v2')
        path=self.f.knowledge/'native-publication-engine.json'
        path.write_bytes((V2.HERE/'knowledge/native-publication-engine.json').read_bytes())
        self.assertEqual(V2.publication_driver(self.index,self.args),'update-native-drivers-v3')
        path.write_text('{"schema":3,"recipe":"unknown","driver":"unreviewed"}',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'publication recipe'):
            V2.publication_driver(self.index,self.args)

    def test_v3_driver_routes_only_publication_and_keeps_parent_native_stage_engine(self):
        driver=load('update-native-drivers-v3')
        parent=SimpleNamespace(run=Mock(return_value={'state':'unchanged_native_result'}))
        v3=object();other=object()
        index=SimpleNamespace(digest=self.index.digest,extension=lambda name:{
            'update-native-drivers-v2':parent,'native-publication-v3':v3,'other':other}[name])
        result=driver.run(index,self.args,self.f.source_sha,self.journal,self.database,cache_only=True)
        self.assertEqual(result,{'state':'unchanged_native_result'})
        proxy=parent.run.call_args.args[0]
        self.assertIs(proxy.extension('native-publication-v2'),v3)
        self.assertIs(proxy.extension('other'),other)
        self.assertIs(index.extension('other'),other)
        self.assertTrue(parent.run.call_args.kwargs['cache_only'])

    def test_regular_update_routes_through_selected_index_and_keeps_profile_gates(self):
        fixture=engine_fixtures.UpdateRunTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        (fixture.knowledge/'update-engine.json').write_bytes((V2.HERE/'knowledge/update-engine.json').read_bytes())
        for name in ('update-run-v2.py','knowledge-scope-v2.py','native-publication-v2.py',
                'update-native-drivers-v2.py','research-scoped-v2.py'):
            # The synthetic engine's HERE remains the product tools directory.
            self.assertTrue((fixture.api.HERE/name).is_file())
        with patch.object(fixture.engine,'ensure_index',side_effect=AssertionError('Legacy global audit')):
            result,_=fixture.run_fixture()
        self.assertEqual(result['state'],'prepared_offline')
        self.assertFalse(result['profile_activation']);self.assertFalse(result['baseline_promoted'])
        self.assertFalse(result['metrics']['scoped_exports']['global_history_verified'])
        self.assertEqual(result['metrics']['native_replays_this_run'],0)
        fixture.args.resume=Path(result['run'])
        again,_=fixture.run_fixture()
        self.assertGreater(again['reused_stages'],0)
        self.assertFalse(again['metrics']['executed_stages'])

    def test_batches_remain_provisional_until_one_owner_barrier(self):
        store=self.args.source_store
        with patch.object(store,'validate',wraps=store.validate) as barrier:
            self.collect();self.collect()
            receipts=self.args._scope_v2_state['scopes']
            self.assertEqual(len(receipts),2)
            for row in receipts:
                self.assertFalse(row['source_barrier_completed'])
                self.assertFalse(row['admission_completed'])
                self.assertTrue(row['pending_owner'])
                self.assertNotIn('validation_sha256',row)
            barrier.assert_not_called()
            finished=V2.finish(self.index,self.args)
            barrier.assert_called_once()
        self.assertTrue(finished['owner_admission']['admission_completed'])
        self.assertTrue(finished['owner_admission']['source_barrier_completed'])

    def test_finished_owner_rejects_more_collection_before_database_write(self):
        self.collect();V2.finish(self.index,self.args)
        before=self.args.scoped_database.read_bytes()
        with self.assertRaisesRegex(ValueError,'закрыт'):
            self.collect()
        self.assertEqual(self.args.scoped_database.read_bytes(),before)

    def test_owner_finishes_after_bundle_preparation_before_pointer_publication(self):
        fixture=engine_fixtures.UpdateRunTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        (fixture.knowledge/'update-engine.json').write_bytes((V2.HERE/'knowledge/update-engine.json').read_bytes())
        real_v2=fixture.api.extension('update-run-v2')
        events=[]
        def finish(index,args):
            events.append('owner')
            self.assertEqual(events,['prepare','owner'])
            return real_v2.finish(index,args)
        fixture.modules['update-run-v2']=SimpleNamespace(enabled=real_v2.enabled,
            ensure_index=real_v2.ensure_index,collect_batches=real_v2.collect_batches,finish=finish)
        publisher=fixture.modules['update-bundle']
        def prepare(*args):
            events.append('prepare')
            return dict(bundles=[],next_profiles={},queue=[],live_verified=False)
        def publish(index,args,bundle,**kwargs):
            events.append('publish')
            self.assertEqual(events,['prepare','owner','publish'])
            return bundle
        publisher.prepare=prepare;publisher.publish=publish
        result,_=fixture.run_fixture()
        self.assertEqual(result['state'],'prepared_offline')
        self.assertEqual(events,['prepare','owner','publish'])


if __name__=='__main__':unittest.main()
