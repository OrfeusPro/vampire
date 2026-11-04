"""Partial declared-resource contexts use content keys, never new admission."""
import ast
import copy
import fnmatch
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from test_vampir_update_contracts import load
import test_vampir_resource_named_tables_v1 as named
import test_vampir_resource_pipeline_v3 as pipeline

KEYS=load('resource-context-keys-v1')
ENGINE=load('update-run')


class ResourceContextKeysTests(named.NamedTableScopeTests):
    def setUp(self):
        super().setUp()
        self.contract=dict(id='quests',coverage='partial',builder=None,context_checks=[],checks=['fixture'],
            resources=[dict(archive='*.pak',path='*Quest*')],recipes=[],depends_on=[],bindings={})
        self.keys_rule=dict(schema=1,recipe=KEYS.RECIPE,contracts={'quests':KEYS.contract_key(named.WORKFLOW,self.contract)})
        self.keys_selector=self.knowledge/'resource-context-keys.json';self.save_keys_rule()
        self.index.read_json=lambda p:json.loads(Path(p).read_bytes())

    def save_keys_rule(self):
        self.keys_selector.write_bytes(named.WORKFLOW.canonical(self.keys_rule))

    def collect(self):
        self.process()
        self.row=dict(path=str(self.archive),current=dict(sha256=named.digest(self.archive),size=self.archive.stat().st_size))
        scope=KEYS.Scope(self.index,self.args)
        scope.observe(self.row,dict(directory=dict(report=self.current_pointer)))
        return scope,scope.inputs(self.contract,[self.row])

    def finish_keys(self,scope):
        pointer=scope.prepare();barrier=self.owner.finish();receipt=scope.publish(barrier)
        return pointer,receipt

    def test_unrelated_content_patch_preserves_selected_key_and_changes_proof(self):
        self.current_tables.append(self.table('CSV/Other.csv','before'))
        first,values=self.collect();_,receipt=self.finish_keys(first)
        self.archive.write_bytes(b'unrelated resource patch')
        self.current_tables[1]=self.table('CSV/Other.csv','changed unrelated payload')
        self.begin();second,again=self.collect();_,next_receipt=self.finish_keys(second)
        self.assertEqual(values,again)
        self.assertNotIn('sha256',values[0])
        self.assertNotEqual(receipt['report'],next_receipt['report'])
        self.assertIs(values[0]['logical_paths_verified'],True)

    def test_matching_payload_change_changes_key(self):
        first,values=self.collect();self.finish_keys(first)
        self.archive.write_bytes(b'matching resource changed')
        self.current_tables[0]=self.table('CSV/Quest.csv','new matching payload')
        self.begin();second,again=self.collect();self.finish_keys(second)
        self.assertNotEqual(values,again)

    def test_added_and_removed_matching_names_change_key(self):
        first,values=self.collect();self.finish_keys(first)
        self.archive.write_bytes(b'matching name added');self.current_tables.append(self.table('CSV/QuestAdded.csv','same'))
        self.begin();second,added=self.collect();self.finish_keys(second)
        self.assertEqual(len(added[0]['entries']),2);self.assertNotEqual(values,added)
        self.archive.write_bytes(b'matching name removed');self.current_tables=self.current_tables[:1]
        self.begin();third,removed=self.collect();self.finish_keys(third)
        self.assertEqual(values,removed)

    def test_complete_empty_match_stays_stable_when_unrelated_archive_changes(self):
        self.current_tables=[self.table('CSV/Other.csv','before')]
        first,values=self.collect();self.finish_keys(first)
        self.assertEqual(values[0]['entries'],[])
        self.archive.write_bytes(b'another unrelated archive patch');self.current_tables=[self.table('CSV/Other.csv','after')]
        self.begin();second,again=self.collect();self.finish_keys(second)
        self.assertEqual(values,again)

    def test_non_csv_matching_assets_are_also_dependencies(self):
        self.unknown_entries=[dict(canonical_path='ProjectRED/Content/QuestAsset.uasset',uncompressed=19,decoded_sha256='a'*64)]
        scope,values=self.collect()
        self.assertEqual(len(values[0]['entries']),2)
        self.assertIn('ProjectRED/Content/QuestAsset.uasset',{e['path'] for e in values[0]['entries']})
        self.finish_keys(scope)

    def test_unknown_matching_hash_keeps_entire_archive_key(self):
        self.unknown_entries=[dict(canonical_path='ProjectRED/Content/QuestAsset.uasset',uncompressed=19,decoded_sha256=None)]
        scope,values=self.collect()
        self.assertIs(values[0]['logical_paths_verified'],False)
        self.assertEqual(values[0]['sha256'],named.digest(self.archive))
        self.assertEqual(scope.contexts['quests']['proof'][0]['reason'],'matching_payload_hash_unknown')
        self.finish_keys(scope)

    def test_unknown_unrelated_payload_does_not_expand_declared_dependencies(self):
        self.unknown_entries=[dict(canonical_path='ProjectRED/Content/Other.uasset',uncompressed=19,decoded_sha256=None)]
        scope,values=self.collect();self.assertIs(values[0]['logical_paths_verified'],True);self.finish_keys(scope)

    def test_full_inventory_gap_forces_archive_fallback(self):
        scope,_=self.collect();scope.documents.clear()
        body=json.loads(Path(self.current_pointer['path']).read_bytes());body['path_gaps']=[dict(reason='fixture unresolved path')]
        pointer=self.snapshot('gap-directory-fixture',body)
        scope.observed[str(self.archive)]['directory']=pointer
        scope.contexts.clear();values=scope.inputs(self.contract,[self.row])
        self.assertIs(values[0]['logical_paths_verified'],False)
        self.assertEqual(scope.contexts['quests']['proof'][0]['reason'],'directory_inventory_incomplete')

    def test_missing_report_preserves_legacy_shape(self):
        scope=KEYS.Scope(self.index,self.args);row=dict(path=str(self.archive),current=dict(sha256=named.digest(self.archive)))
        scope.observe(row,dict(state='requires_review'))
        self.assertEqual(scope.inputs(self.contract,[row]),ENGINE.resource_inputs(self.contract,[row]))

    def test_promoted_builder_or_context_checked_contract_cannot_use_partial_rule(self):
        scope,_=self.collect()
        for field,value in (('coverage','source_checks'),('builder','sdk-launcher'),('context_checks',['version-login-tag'])):
            c=dict(self.contract,**{field:value});self.keys_rule['contracts']['quests']=KEYS.contract_key(named.WORKFLOW,c)
            self.save_keys_rule();self.begin();self.process();scope=KEYS.Scope(self.index,self.args)
            scope.observe(self.row,dict(directory=dict(report=self.current_pointer)))
            self.assertEqual(scope.inputs(c,[self.row]),ENGINE.resource_inputs(c,[self.row]))

    def test_changed_contract_checks_or_resource_pattern_rejects_registered_rule(self):
        scope,_=self.collect()
        for c in (dict(self.contract,checks=['new-check']),dict(self.contract,resources=[dict(archive='*.pak',path='*')])):
            scope.contexts.clear()
            self.assertEqual(scope.inputs(c,[]),[])
            # Separate invocation/contract identity for each request.
            scope.contexts.clear()
            self.assertEqual(scope.inputs(c,[self.row]),ENGINE.resource_inputs(c,[self.row]))
            scope.contexts.clear()

    def test_human_notes_do_not_change_contract_guard(self):
        self.assertEqual(KEYS.contract_key(named.WORKFLOW,self.contract),KEYS.contract_key(named.WORKFLOW,
            dict(self.contract,purpose='описание',limits=['границы'],next_check='следующий шаг')))

    def test_registered_guards_match_real_declarations_and_map_world_dependency(self):
        knowledge=KEYS.HERE/'knowledge'
        rule=json.loads((knowledge/'resource-context-keys.json').read_bytes())
        contracts=json.loads((knowledge/'update-contracts.json').read_bytes())['contracts']
        for c in contracts:
            if c['id'] in rule['contracts']:
                self.assertEqual(rule['contracts'][c['id']],KEYS.contract_key(named.WORKFLOW,c))
                self.assertEqual(c['coverage'],'partial')
        map_contract=next(c for c in contracts if c['id']=='map-data')
        tree=ast.parse((KEYS.HERE/'audit-release-map-projection.py').read_text('utf-8-sig'))
        run=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='run')
        definitions=[n.value for n in ast.walk(run) if isinstance(n,ast.Assign)
            and any(isinstance(t,ast.Name) and t.id=='selected' for t in n.targets)]
        self.assertEqual(len(definitions),1)
        for table in ast.literal_eval(definitions[0]):
            self.assertTrue(any(fnmatch.fnmatchcase('ProjectRED/Content/RED/Data/CSV/'+table+'.csv',d['path'])
                for d in map_contract['resources']),table+' is read by the map audit but not declared')

    def test_source_mismatch_and_different_owner_are_rejected(self):
        scope,_=self.collect();scope.documents.clear();scope.contexts.clear()
        bad=dict(self.row,current=dict(sha256='b'*64))
        with self.assertRaises(ValueError):scope.inputs(self.contract,[bad])
        self.args.resource_directory_v1_scope.owner=object()
        with self.assertRaises(ValueError):scope.inputs(self.contract,[self.row])

    def test_corrupt_directory_pointer_is_rejected(self):
        self.process();scope=KEYS.Scope(self.index,self.args)
        row=dict(path=str(self.archive),current=dict(sha256=named.digest(self.archive)))
        scope.observe(row,dict(directory=dict(report=self.current_pointer)))
        p=Path(self.current_pointer['path']);p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaises(ValueError):scope.inputs(self.contract,[row])

    def test_duplicate_or_unresolved_canonical_names_are_rejected(self):
        for mode in ('duplicate','missing'):
            self.begin();self.process();body=json.loads(Path(self.current_pointer['path']).read_bytes())
            if mode=='duplicate':body['directory_entries'].append(copy.deepcopy(body['directory_entries'][0]))
            else:body['directory_entries'][0]['canonical_path']=None
            p=self.snapshot('malformed-directory-fixtures',body);scope=KEYS.Scope(self.index,self.args)
            row=dict(path=str(self.archive),current=dict(sha256=named.digest(self.archive)))
            scope.observe(row,dict(directory=dict(report=p)))
            with self.assertRaises(ValueError):scope.inputs(self.contract,[row])

    def test_source_change_after_key_prevents_publication(self):
        scope,_=self.collect();scope.prepare();self.archive.write_bytes(b'changed after resource key')
        with self.assertRaises(ValueError):self.owner.finish()
        with self.assertRaises(ValueError):scope.publish({})

    def test_rule_change_after_key_prevents_publication(self):
        scope,_=self.collect();scope.prepare();self.keys_selector.write_bytes(self.keys_selector.read_bytes()+b' ')
        with self.assertRaises(ValueError):self.owner.finish()

    def test_proof_waits_for_owner_and_never_claims_runtime_completeness(self):
        scope,_=self.collect();pointer=scope.prepare()
        with self.assertRaises(ValueError):scope.publish({})
        receipt=scope.publish(self.owner.finish());body=json.loads(Path(receipt['report']).read_bytes())
        self.assertEqual(body['proof'],pointer)
        self.assertIs(body['runtime_dependency_completeness_verified'],False)
        self.assertIs(body['profile_activated'],False)
        with self.assertRaises(ValueError):scope.publish({})
        with self.assertRaises(ValueError):scope.inputs(self.contract,[])

    def test_partial_contract_stage_reuses_after_unrelated_patch(self):
        action=Mock(return_value=dict(state='requires_review',reasons=['Fixture partial contract']))
        record=dict(stages={},state='running')
        journal=ENGINE.Journal(self.index,named.WORKFLOW,self.args,record,self.root/'journal.json')
        self.current_tables.append(self.table('CSV/Other.csv','before'))
        scope,values=self.collect();journal.stage('contract-quests',dict(source='e'*64,resources=values),action);self.finish_keys(scope)
        self.archive.write_bytes(b'unrelated patch');self.current_tables[1]=self.table('CSV/Other.csv','changed')
        self.begin();scope,again=self.collect();journal.stage('contract-quests',dict(source='e'*64,resources=again),action);self.finish_keys(scope)
        self.assertEqual(action.call_count,1);self.assertEqual(journal.reused,1)


class PipelineContextKeyTests(pipeline.ResourcePipelineV3):
    def test_pipeline_collects_keys_then_prepares_and_publishes_with_owner(self):
        self.enable_owner();(self.args.knowledge/'resource-context-keys.json').write_text('{}')
        events=[];hook=Mock();hook.inputs.return_value=[dict(fixture='selected content')]
        hook.prepare.side_effect=lambda:events.append(self.args.resource_owner.state)
        hook.publish.side_effect=lambda barrier:events.append(self.args.resource_owner.state) or dict(proof='fixture')
        original=self.index.extension
        self.index.extension=lambda n:SimpleNamespace(Scope=lambda *a:hook) if n=='resource-context-keys-v1' else original(n)
        p=self.pipeline();result=p.process(self.row)
        self.assertEqual(p.context_inputs({},[]),hook.inputs.return_value)
        finished=p.finish();hook.observe.assert_called_once_with(self.row,result)
        self.assertEqual(events,['open','completed']);self.assertEqual(finished['context_keys'],dict(proof='fixture'))

    def test_ordinary_update_uses_selected_context_inputs_and_records_receipt(self):
        (self.args.knowledge/'update-engine.json').write_bytes((self.index.HERE/'knowledge/update-engine.json').read_bytes())
        selected=[dict(fixture='selected content')];receipt=self.snapshot('fixture-context-keys',dict(semantic_checks_unchanged=True))
        hook=SimpleNamespace(process=Mock(return_value=dict(state='passed')),context_keys=object(),
            context_inputs=Mock(return_value=selected),finish=lambda:dict(context_keys=receipt))
        self.f.modules['resource-pipeline-v3']=SimpleNamespace(enabled=lambda *a:True,
            plan=lambda report,*a:report['files'],Pipeline=Mock(return_value=hook))
        result,_=self.f.run_fixture();record=json.loads(Path(result['run']).read_bytes())['payload']
        self.assertEqual(record['resource_context_keys'],receipt)
        cp=record['stages']['contract-fixture']['result']['context']
        self.assertEqual(json.loads(Path(cp).read_bytes())['resource_inputs'],selected)
        self.assertIs(result['profile_activation'],False)


def load_tests(loader,tests,pattern):
    suite=unittest.TestSuite()
    for cls in (ResourceContextKeysTests,PipelineContextKeyTests):
        suite.addTests(cls(n) for n in sorted(cls.__dict__) if n.startswith('test_'))
    return suite


if __name__=='__main__':unittest.main()
