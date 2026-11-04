"""Resource phases remain independent; caches never grant semantic identity."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_vampir_update_run as fixtures


class ResourcePipelineV3(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.UpdateRunTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.index,self.args,self.root,self.engine,self.workflow=self.f.api,self.f.args,self.f.root,self.f.engine,self.f.workflow
        self.module=self.index.extension('resource-pipeline-v3')
        self.row=dict(path=str(self.f.pak),current=dict(sha256=self.index.digest(self.f.pak),size=self.f.pak.stat().st_size,pak_version=11))
        blob=self.root/'pak-extracted/example/old.bin';blob.parent.mkdir(parents=True);blob.write_bytes(b'previous bytes')
        self.blob=blob
        self.reference=dict(state='available',archive=str(self.f.pak.resolve()),entries=None,
            blobs=[dict(previous_entry=7,file=str(blob),sha256=self.index.digest(blob),observed_paths=['/Game/Observed'])],
            projection_sha256='d'*64,client_version=None,compatibility='not_established')
        self.csv=self.root/'csv/current.csv';self.csv.parent.mkdir();self.csv.write_bytes(b'\xef\xbb\xbfid,name\r\n1,current\r\n')
        self.record=dict(entries=[dict(entry=11,decode_status='decoded',decoded_sha256=self.index.digest(blob))],
            source=self.row['current'],directory_index_parsed=False)
        self.record_ptr=self.snapshot('fixture-records',self.record)
        self.csv_body=dict(state='extracted',tables=[dict(file=str(self.csv),sha256=self.index.digest(self.csv),
            header=['id','name'],rows=1,entry=11,bytes=self.csv.stat().st_size,offset=0,internal_path=None)],errors=[],skipped=0)
        self.csv_ptr=self.snapshot('fixture-current-csv',self.csv_body)
        self.index_api=SimpleNamespace(find=Mock(return_value=self.record_ptr),build=Mock(return_value=self.record_ptr),
            finish=Mock(return_value=dict(source_barrier_completed=True)))
        self.csv_api=SimpleNamespace(extract=Mock(return_value=self.csv_ptr),LIMIT=16*1024*1024)
        self.consumer=SimpleNamespace(select=lambda row:copy.deepcopy(self.reference),
            finish_barrier=Mock(return_value=dict(state='validated',legacy_files_rehashed=0)))
        self.ref_api=SimpleNamespace(open_active=Mock(return_value=self.consumer),
            import_legacy=Mock(return_value={'path':'unused','sha256':'a'*64}),open_snapshot=Mock(return_value=self.consumer))
        original=self.index.extension
        modules={'resource-index-v3':self.index_api,'resource-csv-v3':self.csv_api,'resource-reference-v3':self.ref_api}
        self.index.extension=lambda name:modules[name] if name in modules else original(name)
        self.report=dict(exe=dict(sha256=self.f.sha),files=[self.row])
        self.record_journal=dict(stages={},state='running')

    def snapshot(self,kind,value):
        p=self.workflow.snapshot(self.root,kind,value)
        return dict(path=str(p),sha256=self.index.digest(p))

    def pipeline(self):
        journal=self.engine.Journal(self.index,self.workflow,self.args,self.record_journal,self.root/'journal.json')
        return self.module.Pipeline(self.index,self.args,self.workflow,self.f.update,journal,
            self.args.baseline,self.report,[self.row],{})

    def tables(self,matching=True,empty=False):
        folder=self.root/'table-study';folder.mkdir(exist_ok=True)
        old=folder/'previous.csv';old.write_bytes(b'\xef\xbb\xbfid,name\r\n1,before\r\n')
        rows=[] if empty else [dict(source=dict(path=str(self.f.pak if matching else self.root/'other.pak')),
            file='previous.csv',sha256=self.index.digest(old),header=['id','name'],rows=1)]
        (folder/'index.json').write_text(json.dumps(dict(tables=rows)),encoding='utf-8')
        return old

    def test_foreign_baseline_does_not_block_current_csv_or_content_comparison(self):
        self.tables(matching=False);p=self.pipeline();result=p.process(self.row)
        self.assertEqual(self.csv_api.extract.call_count,1)
        self.assertEqual(result['reasons'],['matching_table_baseline_missing'])
        assets=p.read(result['asset_comparison']);self.assertEqual(assets['exact_content_matches'],1)
        tables=p.read(result['table_comparison']);self.assertEqual(tables['tables'][0]['sha256'],self.index.digest(self.csv))
        self.assertFalse(result['resource_identity_proven']);self.assertFalse(result['directory_index_parsed'])
        self.assertEqual(list((self.root/'knowledge/resource-comparison-cache-v3').glob('*.json')),[])
        self.assertEqual(p.finish()['reference']['legacy_files_rehashed'],0)
        self.assertEqual(len(list((self.root/'knowledge/resource-comparison-cache-v3').glob('*.json'))),2)

    def enable_owner(self):
        (self.args.knowledge/'resource-owner-engine.json').write_text(
            '{"schema":4,"recipe":"resource-owner-sha-v4"}',encoding='utf-8')
        self.consumer.consumed_inputs=lambda:dict(files={},aliases={})

    def test_pipeline_uses_union_owner_before_assigning_comparison_caches(self):
        self.enable_owner();p=self.pipeline();p.process(self.row)
        self.assertFalse(list((self.root/'knowledge/resource-comparison-cache-v3').glob('*.json')))
        result=p.finish()
        self.assertTrue(result['owner']['barrier_completed'])
        self.assertEqual(result['owner']['metrics']['assigned_caches'],2)
        self.assertTrue(result['record_indexes']['source_barrier_completed'])

    def test_owner_failure_and_earlier_index_failure_assign_no_comparison_cache(self):
        self.enable_owner();p=self.pipeline();p.process(self.row)
        self.index_api.finish.side_effect=ValueError('index inventory changed')
        with self.assertRaisesRegex(ValueError,'inventory'):p.finish()
        self.assertTrue(p.owner.closed)
        self.assertFalse(list((self.root/'knowledge/resource-comparison-cache-v3').glob('*.json')))

    def test_owner_catches_reference_bytes_changed_after_reference_barrier(self):
        self.enable_owner()
        active=self.root/'active-reference.json';active.write_bytes(b'active reference')
        self.consumer.consumed_inputs=lambda:dict(files={str(active):self.index.digest(active)},aliases={})
        self.consumer.finish_barrier.side_effect=lambda:active.write_bytes(b'changed reference')
        p=self.pipeline();p.process(self.row)
        with self.assertRaisesRegex(ValueError,'input'):p.finish()
        self.assertFalse(list((self.root/'knowledge/resource-comparison-cache-v3').glob('*.json')))

    def test_owner_catches_warm_comparison_pointer_changed_before_final_barrier(self):
        self.enable_owner();p=self.pipeline();p.process(self.row);p.finish()
        p=self.pipeline();p.process(self.row)
        pointer=next((self.root/'knowledge/resource-comparison-cache-v3').glob('*.json'))
        pointer.write_bytes(b'corrupt late pointer')
        with self.assertRaisesRegex(ValueError,'input'):p.finish()

    def test_available_matching_tables_use_exact_old_comparison_functions(self):
        old=self.tables();p=self.pipeline();result=p.process(self.row)
        self.assertEqual(result['state'],'passed')
        tables=p.read(result['table_comparison']);self.assertEqual(tables['comparison']['unique_schema_candidates'],1)
        self.assertEqual(tables['tables'][0]['candidate_row_diff']['changed_rows'],1)
        self.assertFalse(tables['tables'][0]['identity_proven_by_schema']);p.finish()

    def test_empty_selected_table_catalogue_is_an_explicit_missing_baseline(self):
        self.tables(empty=True);p=self.pipeline();result=p.process(self.row)
        self.assertIn('matching_table_baseline_missing',result['reasons']);p.finish()

    def test_missing_reference_does_not_block_current_extraction(self):
        self.reference.update(state='missing',blobs=[]);p=self.pipeline();result=p.process(self.row)
        self.csv_api.extract.assert_called_once();self.assertIn('historical_blob_reference_missing',result['reasons'])
        p.finish()

    def test_first_import_and_reused_active_snapshot_are_distinct(self):
        self.ref_api.open_active.return_value=None;p=self.pipeline();p.process(self.row)
        self.ref_api.import_legacy.assert_called_once();self.ref_api.open_snapshot.assert_called_once();p.finish()

    def test_index_is_built_only_if_no_checked_record_is_available(self):
        self.index_api.find.return_value=None;p=self.pipeline();p.process(self.row)
        self.index_api.build.assert_called_once();p.finish()

    def test_partial_csv_reports_and_original_entries_remain_reviewable(self):
        self.csv_body.update(state='partial',errors=[dict(entry=11,error_type='ValueError')])
        self.csv_api.extract.return_value=self.snapshot('fixture-current-csv',self.csv_body)
        p=self.pipeline();result=p.process(self.row)
        self.assertIn('current_csv_extraction_errors',result['reasons'])
        self.assertTrue(result['owner_barrier_pending']);p.finish()

    def test_durable_comparison_pointer_is_not_earned_after_mutated_output(self):
        p=self.pipeline();p.process(self.row);self.csv.write_bytes(self.csv.read_bytes()+b'!')
        with self.assertRaisesRegex(ValueError,'bytes changed'):p.finish()
        self.assertFalse(list((self.root/'knowledge/resource-comparison-cache-v3').glob('*.json')))

    def test_missing_table_catalogue_created_midrun_blocks_finalization(self):
        p=self.pipeline();p.process(self.row);self.tables()
        with self.assertRaisesRegex(ValueError,'appeared or disappeared'):p.finish()

    def test_foreign_catalogue_mutation_is_detected_by_standalone_pipeline(self):
        self.tables(matching=False);p=self.pipeline();p.process(self.row);self.tables(matching=True)
        with self.assertRaisesRegex(ValueError,'bytes changed'):p.finish()

    def test_new_rule_changes_comparison_key_and_caches_are_reused_only_after_validation(self):
        p=self.pipeline();first=p.process(self.row);p.finish()
        p=self.pipeline();again=p.process(self.row)
        self.assertEqual(first['asset_comparison'],again['asset_comparison'])
        self.assertEqual(p.metrics['comparison_cache_hits'],2);p.finish()
        p=self.pipeline();marker=self.root/'new-reviewed-rule';marker.write_bytes(b'new algorithm')
        p.rules[str(marker)]=p.pin(marker)
        changed=p.process(self.row);self.assertNotEqual(first['asset_comparison'],changed['asset_comparison']);p.finish()

    def test_corrupt_cached_comparison_is_not_silently_recomputed(self):
        p=self.pipeline();result=p.process(self.row);p.finish()
        Path(result['asset_comparison']['path']).write_bytes(b'bad')
        p=self.pipeline();result=p.process(self.row)
        self.assertEqual(result['reasons'],['resource_processing_rejected'])
        self.assertIn('SHA differs',result['reason'])

    def test_report_alias_retarget_is_guarded_even_for_identical_bytes(self):
        p=self.pipeline();original=Path.resolve;report=Path(self.record_ptr['path'])
        alias=self.root/'alias.json';alternate=self.root/'alternative.json'
        alternate.write_bytes(report.read_bytes());target=[original(report)]
        def resolve(path,*args,**kwargs):
            return target[0] if path==alias else original(path,*args,**kwargs)
        with patch.object(Path,'resolve',resolve):
            p.read(dict(path=str(alias),sha256=self.record_ptr['sha256']));target[0]=original(alternate)
            with self.assertRaisesRegex(ValueError,'alias changed'):p.finish()

    def test_plan_and_selector_are_explicit_without_extraction_or_legacy_import(self):
        contracts=dict(contracts=[dict(resources=[dict(archive='*.pak',path='*')])])
        self.assertEqual(self.module.plan(self.report,contracts,[]),[self.row])
        self.assertFalse(self.module.enabled(self.index,self.args))
        (self.args.knowledge/'resource-pipeline-engine.json').write_text('{}',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'recipe ресурсов'):self.module.enabled(self.index,self.args)
        self.csv_api.extract.assert_not_called();self.ref_api.import_legacy.assert_not_called()

    def test_ordinary_update_routes_resources_and_finishes_them_before_publication(self):
        (self.args.knowledge/'update-engine.json').write_bytes((self.index.HERE/'knowledge/update-engine.json').read_bytes())
        events=[]
        pipeline=SimpleNamespace(process=Mock(return_value=dict(state='requires_review',reason='matching_table_baseline_missing',
            reasons=['matching_table_baseline_missing'])),finish=lambda:(events.append('resources') or {'state':'validated'}))
        module=SimpleNamespace(enabled=lambda *args:True,plan=lambda report,*args:report['files'],Pipeline=Mock(return_value=pipeline))
        self.f.modules['resource-pipeline-v3']=module
        publisher=self.f.modules['update-bundle']
        def publish(index,args,bundle,**kwargs):
            events.append('publish');self.assertEqual(events,['resources','publish']);return bundle
        publisher.publish=publish
        result,_=self.f.run_fixture()
        self.assertEqual(result['state'],'needs_review')
        pipeline.process.assert_called_once()
        self.assertEqual(result['metrics']['resource_pipeline']['state'],'validated')
        self.assertEqual(events,['resources','publish'])

    def test_common_missing_table_blocker_is_grouped_across_archives(self):
        contracts=dict(contracts=[dict(id='data',depends_on=[],resources=[dict(archive='*.pak',path='*')])],
            capabilities={'map':dict(requires=['data'])},order=['data'])
        queue=[dict(contract=None,capability='resources',archive=str(self.root/(name+'.pak')),
            reason='matching_table_baseline_missing',evidence=dict(recipe='resource-pipeline-v3')) for name in ('a','b','c')]
        groups=self.engine.root_blockers(contracts,{},queue)
        self.assertEqual(len(groups),1);self.assertEqual(groups[0]['observations'],3)
        self.assertEqual(groups[0]['contracts'],['data']);self.assertEqual(len(groups[0]['resources']),3)

    def test_changed_exe_config_failure_cannot_reuse_cached_passed_resource(self):
        self.tables()
        core=self.index.extension('recover-pak-game-config')
        provenance=self.root/'resource-config-snapshots/393c0697115ec6beceeb0e822bed0f6907eab83dfe9a47f81e9c7875deff35db/manifest.json'
        provenance.parent.mkdir(parents=True);provenance.write_bytes(b'{}')
        exe=self.root/'client-code-snapshots'/core.EXE_SHA256/'ProjectRED-Win64-Shipping.exe'
        exe.parent.mkdir(parents=True,exist_ok=True);exe.write_bytes(b'explicit historical key source')
        row=dict(self.row,path=str(self.f.pak.with_name('ProjectRED-Windows.pak')))
        # Keep the exact same selected table projection in this orchestration
        # fixture while changing only EXE/config, as a real unchanged PAK does.
        baseline=self.engine.table_baseline(self.index,self.args,self.row)
        with patch.object(self.engine,'table_baseline',return_value=baseline), \
                patch.object(self.f.update,'execute_adapter',return_value=dict(state='passed')):
            p=self.pipeline();first=p.process(row);p.finish()
        self.assertEqual(first['state'],'passed')
        self.report['exe']['sha256']='b'*64
        with patch.object(self.engine,'table_baseline',return_value=baseline), \
                patch.object(self.f.update,'execute_adapter',return_value=dict(state='requires_review',reason='changed configuration')):
            p=self.pipeline();second=p.process(row);p.finish()
        self.assertEqual(second['state'],'requires_review')
        self.assertIn('current_game_config_extraction_incomplete',second['reasons'])


if __name__=='__main__':unittest.main()
