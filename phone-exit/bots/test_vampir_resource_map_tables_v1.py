"""Map table data can be reused independently of pending native projection."""
import copy
import csv
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from test_vampir_update_contracts import load
import test_vampir_resource_pipeline_v3 as pipeline

MAP=load('resource-map-tables-v1')
CSV=load('resource-csv-v3')
OWNER=load('resource-owner-v4')
WORKFLOW=load('research-workflow')


def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()


class MapTableDataTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve();self.knowledge=self.root/'registry';self.knowledge.mkdir()
        (self.knowledge/'resource-owner-engine.json').write_bytes(WORKFLOW.canonical(dict(schema=4,recipe='resource-owner-sha-v4')))
        self.exe=self.root/'installed/client.exe';self.exe.parent.mkdir();self.exe.write_bytes(b'public synthetic current client')
        self.archive=self.exe.parent/'Patch/Install/pakchunk1-Windows.pak';self.archive.parent.mkdir(parents=True)
        self.archive.write_bytes(b'public synthetic current PAK')
        self.report=dict(exe=dict(path=str(self.exe),sha256=digest(self.exe)))
        self.maps=[dict(Id=str(n),MapResource='Field/Fixture',GroundDistance='100',CenterX='0',CenterY='0') for n in (10,11)]
        self.worlds=[dict(Id=str(n),MapId=str(10+n%2),LevelPath='Field/World'+str(n),Other='unchanged') for n in range(100,136)]
        self.baseline=self.make_baseline()
        self.rule=dict(schema=1,recipe=MAP.RECIPE,archive='*/Patch/Install/pakchunk1-Windows.pak',
            baseline=self.baseline,tables=copy.deepcopy(MAP.TABLES))
        self.selector=self.knowledge/'resource-map-tables.json';self.selector.write_bytes(WORKFLOW.canonical(self.rule))
        self.directory_rules=dict(fixture='verified current reader');self.directory_runtime=dict(fixture='runtime')
        self.index=SimpleNamespace(HERE=MAP.HERE,digest=digest,read_json=lambda p:json.loads(Path(p).read_bytes()),
            extension=lambda n:{'research-workflow':WORKFLOW,'resource-csv-v3':CSV}[n])
        self.args=SimpleNamespace(root=self.root,knowledge=self.knowledge)
        self.owner=None;self.begin()

    def snapshot(self,category,body):
        p=WORKFLOW.snapshot(self.root,category,body);return dict(path=str(p),sha256=digest(p))

    def blob(self,name,rows):
        text=io.StringIO(newline='');writer=csv.DictWriter(text,list(rows[0]),lineterminator='\r\n')
        writer.writeheader();writer.writerows(rows);raw=b'\xef\xbb\xbf'+text.getvalue().encode()
        sha=hashlib.sha256(raw).hexdigest();p=self.root/'inputs'/sha/(name+'.csv');p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
        return dict(path=str(p),sha256=sha)

    def make_baseline(self):
        artifacts=dict(Map=self.blob('Map',self.maps),World=self.blob('World',self.worlds))
        geometry=dict(size=[1000,1000],center=[0,0],ground_distance=100)
        projection=dict(map_records=self.maps,map_ids=['10','11'],**geometry)
        raw=WORKFLOW.canonical(projection);p=self.root/'inputs'/hashlib.sha256(raw).hexdigest()/'projection.json'
        p.parent.mkdir(parents=True);p.write_bytes(raw);artifacts['projection']=dict(path=str(p),sha256=digest(p))
        table=self.snapshot('captured-table-fixtures',dict(tables=[dict(sha256=artifacts[n]['sha256']) for n in ('Map','World')]))
        worlds={v['Id']:dict(MapId=v['MapId'],LevelPath=v['LevelPath']) for v in self.worlds}
        parent=self.snapshot('reviewed-map-audit-fixtures',dict(source_sha256='a'*64,table_manifest=table,
            atlas_projection_sha256=artifacts['projection']['sha256'],tables={n:dict(sha256=artifacts[n]['sha256']) for n in ('Map','World')},
            worlds={k:v['MapId'] for k,v in worlds.items()}))
        return self.snapshot('reviewed-map-baseline-fixtures',dict(schema=1,recipe='reviewed-map-table-baseline-v1',
            source_sha256='a'*64,parent=parent,historical_table_manifest=table,artifacts=artifacts,map_ids=['10','11'],
            maps=copy.deepcopy(self.maps),worlds=worlds,geometry=geometry))

    def begin(self):
        if self.owner is not None and not self.owner.closed:self.owner.abort()
        self.owner=OWNER.begin(self.index,self.args)
        self.args.resource_directory_v1_scope=SimpleNamespace(owner=self.owner,rules=self.directory_rules,runtime=self.directory_runtime)
        self.scope=MAP.Scope(self.index,self.args,self.report)
        self.addCleanup(lambda o=self.owner:o.abort() if not o.closed else None)

    def directory(self,maps=None,worlds=None):
        bindings=[]
        for name,rows in (('Map',maps or self.maps),('World',worlds or self.worlds)):
            p=self.blob('current-'+name,rows)
            bindings.append(dict(canonical_path=MAP.TABLES[name],file=p['path'],sha256=p['sha256'],bytes=Path(p['path']).stat().st_size,
                header=list(rows[0]),rows=len(rows),directory_identity_verified=True))
        row=dict(path=str(self.archive),current=dict(sha256=digest(self.archive)))
        body=dict(recipe='resource-directory-v1',authoritative_directory_for_archive=True,
            inputs=dict(source=dict(path=str(self.archive),sha256=digest(self.archive)),rules=self.directory_rules,runtime=self.directory_runtime),
            csv_bindings=bindings,path_gaps=[],unmatched_csv=[])
        return row,body

    def collect(self,maps=None,worlds=None,mutate=None):
        row,body=self.directory(maps,worlds)
        if mutate:mutate(body)
        pointer=self.snapshot('current-directory-fixtures',body)
        self.scope.observe(row,dict(directory=dict(report=pointer)))
        self.current_directory=pointer;self.current_body=body
        result=self.scope.prepare();return self.index.read_json(result['path'])

    def test_current_maps_and_36_world_bindings_match_without_native_promotion(self):
        result=self.collect()
        self.assertEqual((result['state'],result['matched_maps'],result['matched_worlds']),('data_matched',2,36))
        for k in ('target_native_projection_verified','runtime_activated','profile_activated','historical_archive_freshly_hashed'):
            self.assertIs(result[k],False)
        self.assertEqual(self.scope.metrics['current_rows'],38)

    def test_warm_data_analysis_is_reused_with_new_owner_receipt(self):
        first=self.collect();one=self.scope.publish(self.owner.finish())
        self.begin();second=self.collect();two=self.scope.publish(self.owner.finish())
        self.assertEqual(first,second)
        self.assertEqual(self.scope.metrics['cache_hits'],1);self.assertEqual(self.scope.metrics['analyses'],0)
        self.assertEqual(one['data'],two['data']);self.assertNotEqual(one['report'],two['report'])

    def test_cache_publication_waits_for_owner_and_changed_source_aborts(self):
        self.collect();self.assertEqual(list((self.root/'knowledge/resource-comparison-cache-v3').glob('*')),[])
        with self.assertRaises(ValueError):self.scope.publish({})
        self.archive.write_bytes(b'mutated archive')
        with self.assertRaises(ValueError):self.owner.finish()
        with self.assertRaises(ValueError):self.scope.publish({})

    def test_changed_client_after_analysis_blocks_publication(self):
        self.collect();self.exe.write_bytes(b'new client patch')
        with self.assertRaises(ValueError):self.owner.finish()

    def test_changed_map_data_and_column_layout_are_concrete_review_reasons(self):
        maps=copy.deepcopy(self.maps);maps[0]['GroundDistance']='101'
        result=self.collect(maps=maps)
        self.assertIn('reviewed_map_rows_changed',result['reasons']);self.assertEqual(result['state'],'requires_review')
        self.begin();maps=copy.deepcopy(self.maps)
        for r in maps:r['AddedColumn']='unknown'
        result=self.collect(maps=maps);self.assertIn('map_table_columns_changed',result['reasons'])

    def test_changed_world_level_or_map_binding_is_detected(self):
        for field,value in (('LevelPath','Field/Changed'),('MapId','12')):
            self.begin();worlds=copy.deepcopy(self.worlds);worlds[0][field]=value
            result=self.collect(worlds=worlds)
            self.assertIn('reviewed_world_membership_or_binding_changed',result['reasons'])

    def test_added_or_removed_member_world_requires_review(self):
        worlds=copy.deepcopy(self.worlds)+[dict(Id='999',MapId='10',LevelPath='New',Other='')]
        result=self.collect(worlds=worlds);self.assertEqual(result['world_ids_added'],['999'])
        self.begin();result=self.collect(worlds=self.worlds[1:]);self.assertEqual(result['world_ids_missing'],['100'])

    def test_unconsumed_world_fields_and_unrelated_worlds_do_not_change_data_verdict(self):
        worlds=copy.deepcopy(self.worlds)
        for r in worlds:r['Other']='changed outside this rule'
        worlds.append(dict(Id='999',MapId='12',LevelPath='New',Other=''))
        result=self.collect(worlds=worlds);self.assertEqual(result['state'],'data_matched')

    def test_unrelated_map_rows_do_not_become_projection_members(self):
        maps=copy.deepcopy(self.maps)+[dict(self.maps[0],Id='12',GroundDistance='999')]
        result=self.collect(maps=maps);self.assertEqual(result['state'],'data_matched');self.assertEqual(result['matched_maps'],2)

    def test_world_projection_columns_are_required(self):
        worlds=[{k:v for k,v in r.items() if k!='LevelPath'} for r in self.worlds]
        result=self.collect(worlds=worlds);self.assertIn('world_projection_columns_missing',result['reasons'])

    def test_duplicate_ids_or_malformed_rows_do_not_acquire_a_verdict(self):
        worlds=copy.deepcopy(self.worlds)+[copy.deepcopy(self.worlds[0])]
        with self.assertRaises(ValueError):self.collect(worlds=worlds)
        for raw in (b'Id,A\n1,2\n',b'\xef\xbb\xbfId,A\r\n1\r\n',b'\xef\xbb\xbfId,Id\r\n1,1\r\n'):
            with self.assertRaises(ValueError):MAP.table_rows(raw)

    def test_missing_archive_directory_and_payload_remain_explicit(self):
        p=self.scope.prepare();self.assertEqual(self.index.read_json(p['path'])['reasons'],['map_table_archive_not_observed'])
        self.begin();self.scope.observe(dict(path=str(self.archive),current=dict(sha256=digest(self.archive))),{})
        p=self.scope.prepare();self.assertEqual(self.index.read_json(p['path'])['reasons'],['map_table_directory_missing'])
        self.begin();result=self.collect(mutate=lambda d:d['csv_bindings'].pop())
        self.assertEqual(result['reasons'],['map_table_payload_missing_or_ambiguous:World'])

    def test_incomplete_directory_and_ambiguous_table_cannot_be_matched(self):
        result=self.collect(mutate=lambda d:d['path_gaps'].append(dict(reason='unknown')))
        self.assertEqual(result['reasons'],['map_table_directory_incomplete'])
        self.begin();result=self.collect(mutate=lambda d:d['csv_bindings'].append(copy.deepcopy(d['csv_bindings'][0])))
        self.assertEqual(result['reasons'],['map_table_payload_missing_or_ambiguous:Map'])

    def test_wrong_directory_source_rule_or_owner_is_rejected(self):
        for key,value in (('source',dict(path=str(self.archive),sha256='b'*64)),('rules',{}),('runtime',{})):
            self.begin()
            with self.assertRaises(ValueError):self.collect(mutate=lambda d,k=key,v=value:d['inputs'].__setitem__(k,v))
        self.begin();self.args.resource_directory_v1_scope.owner=object()
        with self.assertRaises(ValueError):self.collect()

    def test_current_payload_hash_size_and_metadata_are_verified(self):
        for key,value in (('sha256','b'*64),('bytes',0),('rows',999),('header',['Id']),('directory_identity_verified',False)):
            self.begin()
            with self.assertRaises(ValueError):self.collect(mutate=lambda d,k=key,v=value:d['csv_bindings'][0].__setitem__(k,v))

    def test_selector_change_and_historical_payload_damage_block_owner(self):
        self.collect();self.selector.write_bytes(self.selector.read_bytes()+b' ')
        with self.assertRaises(ValueError):self.owner.finish()
        self.selector.write_bytes(WORKFLOW.canonical(self.rule));self.begin();self.collect()
        b=self.index.read_json(self.baseline['path']);p=Path(b['artifacts']['World']['path']);p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaises(ValueError):self.owner.finish()

    def test_baseline_geometry_rows_and_ancestry_cannot_be_relabelled(self):
        b=self.index.read_json(self.baseline['path'])
        for mutate in (lambda v:v['geometry'].__setitem__('ground_distance',101),
                lambda v:v['maps'][0].__setitem__('MapResource','Changed'),lambda v:v.__setitem__('source_sha256','b'*64)):
            value=copy.deepcopy(b);mutate(value);self.rule['baseline']=self.snapshot('bad-baseline-fixtures',value)
            self.selector.write_bytes(WORKFLOW.canonical(self.rule))
            with self.assertRaises(ValueError):self.begin()

    def test_corrupt_warm_analysis_does_not_silently_rebuild(self):
        self.collect();receipt=self.scope.publish(self.owner.finish());p=Path(receipt['data']['path']);p.write_bytes(p.read_bytes()+b' ')
        self.begin()
        with self.assertRaises(ValueError):self.collect()

    def test_publication_checks_epoch_and_content_and_runs_once(self):
        self.collect();barrier=self.owner.finish();p=Path(barrier['report']);raw=p.read_bytes();p.write_bytes(raw+b' ')
        with self.assertRaises(ValueError):self.scope.publish(barrier)
        p.write_bytes(raw);self.scope.publish(barrier)
        with self.assertRaises(ValueError):self.scope.publish(barrier)

    def test_unknown_selector_schema_and_absent_rule_are_rejected(self):
        for field,value in (('schema',True),('recipe','unknown'),('archive','*')):
            self.selector.write_bytes(WORKFLOW.canonical(dict(self.rule,**{field:value})))
            with self.assertRaises(ValueError):MAP.configuration(self.args)
        self.selector.unlink();self.assertIsNone(MAP.configuration(self.args))


class MapPipelineTests(pipeline.ResourcePipelineV3):
    def test_normal_pipeline_observes_and_publishes_after_shared_barrier(self):
        self.enable_owner();(self.args.knowledge/'resource-map-tables.json').write_text('{}')
        events=[];hook=Mock();hook.prepare.side_effect=lambda:events.append(self.args.resource_owner.state)
        hook.publish.side_effect=lambda owner:events.append(self.args.resource_owner.state) or dict(state='data_matched')
        original=self.index.extension
        self.index.extension=lambda n:SimpleNamespace(Scope=lambda *a:hook) if n=='resource-map-tables-v1' else original(n)
        p=self.pipeline();result=p.process(self.row);finished=p.finish()
        hook.observe.assert_called_once_with(self.row,result);self.assertEqual(events,['open','completed'])
        self.assertEqual(finished['map_tables'],dict(state='data_matched'))

    def test_regular_update_exposes_data_failure_and_keeps_partial_readiness(self):
        (self.args.knowledge/'update-engine.json').write_bytes((self.index.HERE/'knowledge/update-engine.json').read_bytes())
        data=dict(state='requires_review',reasons=['changed field'],target_native_projection_verified=False)
        hook=SimpleNamespace(process=Mock(return_value=dict(state='passed')),finish=lambda:dict(map_tables=data))
        self.f.modules['resource-pipeline-v3']=SimpleNamespace(enabled=lambda *a:True,plan=lambda r,*a:r['files'],Pipeline=Mock(return_value=hook))
        result,_=self.f.run_fixture();record=json.loads(Path(result['run']).read_bytes())['payload']
        self.assertEqual(record['map_table_data'],data);self.assertEqual(result['state'],'needs_review')
        self.assertTrue(any(q['reason']=='map_table_data_requires_review' for q in record['queue']))
        self.assertIs(result['profile_activation'],False)


def load_tests(loader,tests,pattern):
    suite=unittest.TestSuite()
    for cls in (MapTableDataTests,MapPipelineTests):
        suite.addTests(cls(n) for n in sorted(cls.__dict__) if n.startswith('test_'))
    return suite


if __name__=='__main__':unittest.main()
