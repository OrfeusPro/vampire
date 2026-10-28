import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_vampir_research_update as fixture


class UpdateRunTests(fixture.ResearchUpdateTests):
    def test_shared_tool_dependencies_are_parsed_once_per_snapshot_and_revalidated(self):
        folder=self.root/'tools';folder.mkdir()
        seeds=('recover-release-game-config.py','index-release-archives.py','compare-release-assets.py',
            'extract-release-tables.py','locate-release-update-targets.py','update-bindings.py',
            'update-contracts.py','verify-version-login-context.py','verify-packet-writer-context.py',
            'update-native-harness.py','update-profile.py')
        common=('update-run.py','research-update.py','research-workflow.py','knowledge-index.py','knowledge-context.py')
        for name in set(seeds+common):(folder/name).write_text("'shared-helper'",encoding='utf-8')
        shared=folder/'shared-helper.py';shared.write_text("'unique_shared_marker'",encoding='utf-8')
        api=SimpleNamespace(HERE=folder,digest=self.index.digest,
            extension=lambda name:SimpleNamespace(runtime_inputs=lambda:{}))
        original=self.engine.ast.parse
        with patch.dict(self.engine.os.environ,{'PHONEEXIT_RF_RESOURCES':str(self.root/'rf')}), \
             patch.object(self.engine.ast,'parse',wraps=original) as parser:
            first=self.real_execution_inputs(api)
            self.assertEqual(sum(c.args[0]=="'unique_shared_marker'" for c in parser.call_args_list),1)
            shared.write_text("'changed_shared_marker'",encoding='utf-8')
            second=self.real_execution_inputs(api)
            self.assertEqual(sum(c.args[0]=="'changed_shared_marker'" for c in parser.call_args_list),1)
        self.assertEqual(set(first),set(second))
        for name in first:
            self.assertNotEqual(first[name][str(shared.resolve())],second[name][str(shared.resolve())])

    # Reuse the synthetic installation factory, not its inherited test methods.
    def setUp(self):
        super().setUp()
        self.engine = self.index.extension('update-run')
        self.real_execution_inputs=self.engine.execution_inputs
        self.tools={name:dict(fixture='tool-v1') for name in ('resources','discovery','bindings','contracts','context','profile')}
        mocked=patch.object(self.engine,'execution_inputs',return_value=self.tools)
        mocked.start();self.addCleanup(mocked.stop)
        self.model = self.index.extension('update-contracts')
        self.bindings = self.index.extension('update-bindings')
        self.modules = {'research-workflow':self.workflow,'research-update':self.update,
            'update-run':self.engine,'update-contracts':self.model,'update-bindings':self.bindings,
            'update-bundle':SimpleNamespace(prepare=lambda *args:dict(bundles=[],next_profiles={},queue=[],live_verified=False))}
        api = self.index.api(); original = api.extension
        api.extension = lambda name:self.modules[name] if name in self.modules else original(name)
        self.api = api
        contract = dict(id='fixture',purpose='fixture',depends_on=[],checks=['fixture-check'],recipes=[],bindings={},resources=[],
            coverage='source_checks',builder=None,limits=['Synthetic check'],next_check='Inspect fixture')
        self.contracts = dict(schema=1,capabilities={'fixture':dict(requires=['fixture'])},contracts=[contract])
        (self.knowledge/'update-contracts.json').write_text(json.dumps(self.contracts),'utf-8')
        (self.knowledge/'release-update-targets.json').write_text(json.dumps(dict(anchors=[])),'utf-8')
        (self.knowledge/'research-checks.json').write_text(json.dumps(dict(checks=[dict(id='fixture-check')])),'utf-8')
        self.args.plan_only=False; self.args.resume=None

    def run_fixture(self):
        with patch.object(self.bindings,'resolve',return_value=dict(contracts={'fixture':dict(bindings={},queue=[])})), \
                patch.object(self.workflow,'run_checks',return_value=[dict(id='fixture-check',state='passed')]), \
                patch.object(self.update,'execute_adapter',return_value=dict(state='passed',result=dict(candidates=[]))) as adapter:
            result = self.engine.run(self.api,self.args,self.root/'knowledge/search.sqlite3')
        return result,adapter.call_count

    def test_plan_only_never_starts_analysis_checks_or_builder(self):
        self.args.plan_only=True
        with patch.object(self.update,'execute_adapter',side_effect=AssertionError('Must not execute')), \
                patch.object(self.workflow,'run_checks',side_effect=AssertionError('Must not check')):
            result=self.engine.run(self.api,self.args,self.root/'knowledge/search.sqlite3')
        self.assertEqual(result['state'],'planned')
        self.assertFalse(result['profile_activation'])

    def test_context_adapters_keep_separate_cached_results(self):
        self.contracts['contracts'][0]['context_checks']=['version-login-tag','packet-writer-projection']
        (self.knowledge/'update-contracts.json').write_text(json.dumps(self.contracts),'utf-8')
        tag=Mock(return_value=dict(proof='tag'))
        writer=Mock(return_value=dict(proof='writer'))
        self.modules['verify-version-login-context']=SimpleNamespace(verify=tag)
        self.modules['verify-packet-writer-context']=SimpleNamespace(verify=writer)
        first,_=self.run_fixture()
        self.assertEqual(tag.call_count,1)
        self.assertEqual(writer.call_count,1)
        self.args.resume=Path(first['run'])
        self.run_fixture()
        self.assertEqual(tag.call_count,1)
        self.assertEqual(writer.call_count,1)

    def test_resume_reuses_completed_stages_and_status_is_read_only(self):
        first,calls=self.run_fixture()
        self.args.resume=Path(first['run'])
        second,again=self.run_fixture()
        self.assertEqual(calls,1); self.assertEqual(again,0)
        self.assertGreater(second['reused_stages'],0)
        self.assertEqual(first['state'],'prepared_offline')
        before=Path(first['run']).read_bytes()
        result=self.engine.status(self.api,SimpleNamespace(root=self.root,run=Path(first['run'])))
        self.assertEqual(Path(first['run']).read_bytes(),before)
        self.assertFalse(result['baseline_promoted']); self.assertFalse(result['profile_activation'])

    def test_plan_can_continue_into_execution(self):
        self.args.plan_only=True
        first,_=self.run_fixture()
        self.args.plan_only=False;self.args.resume=Path(first['run'])
        second,calls=self.run_fixture()
        self.assertEqual(second['state'],'prepared_offline');self.assertEqual(calls,1)

    def test_journal_interruption_keeps_completed_work(self):
        path=self.root/'knowledge/update-runs/fixture/run.json'
        run=dict(stages={})
        journal=self.engine.Journal(self.api,self.workflow,self.args,run,path)
        stable=Mock(return_value=dict(value=1))
        journal.stage('one',dict(input=1),stable)
        with self.assertRaises(KeyboardInterrupt):
            journal.stage('two',dict(input=2),Mock(side_effect=KeyboardInterrupt()))
        restored=self.engine.read(self.api,self.workflow,path,self.root)
        journal=self.engine.Journal(self.api,self.workflow,self.args,restored,path)
        journal.stage('one',dict(input=1),stable)
        journal.stage('two',dict(input=2),lambda:dict(value=2))
        stable.assert_called_once()
        self.assertEqual(restored['stages']['two']['state'],'completed')

    def test_corrupt_saved_output_is_not_reused(self):
        path=self.root/'knowledge/update-runs/fixture/run.json'
        report=self.workflow.snapshot(self.root,'fixtures',dict(value=1))
        journal=self.engine.Journal(self.api,self.workflow,self.args,dict(stages={}),path)
        journal.stage('one',dict(input=1),lambda:dict(report=str(report)))
        report.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError,'output changed'):
            journal.stage('one',dict(input=1),lambda:dict(value=2))

    def test_dependency_input_change_repeats_only_affected_stage(self):
        path=self.root/'knowledge/update-runs/fixture/run.json'
        journal=self.engine.Journal(self.api,self.workflow,self.args,dict(stages={}),path)
        a,b=Mock(return_value={}),Mock(return_value={})
        journal.stage('a',dict(sha=1),a);journal.stage('b',dict(sha=1),b)
        journal.stage('a',dict(sha=1),a);journal.stage('b',dict(sha=2),b)
        self.assertEqual(a.call_count,1);self.assertEqual(b.call_count,2)

    def test_profile_tool_change_does_not_invalidate_resource_or_discovery_tools(self):
        folder=self.root/'isolated-tools';folder.mkdir()
        for name in ('update-profile.py','update-bundle.py','update-run.py','research-update.py',
                'research-workflow.py','knowledge-index.py','knowledge-context.py'):
            (folder/name).write_text('',encoding='utf-8')
        api=SimpleNamespace(HERE=folder,digest=self.index.digest,
            extension=lambda name:SimpleNamespace(runtime_inputs=lambda:{}))
        before=self.real_execution_inputs(api)
        (folder/'update-profile.py').write_text('# changed profile only',encoding='utf-8')
        after=self.real_execution_inputs(api)
        self.assertEqual(before['resources'],after['resources'])
        self.assertEqual(before['discovery'],after['discovery'])
        self.assertNotEqual(before['profile'],after['profile'])

    def test_cli_change_does_not_invalidate_processing_stage_keys(self):
        folder=self.root/'cli-tools';folder.mkdir()
        (folder/'knowledge-index.py').write_text('# old entry point',encoding='utf-8')
        api=SimpleNamespace(HERE=folder,digest=self.index.digest,
            extension=lambda name:SimpleNamespace(runtime_inputs=lambda:{}))
        before=self.real_execution_inputs(api)
        (folder/'knowledge-index.py').write_text('# changed CLI formatting',encoding='utf-8')
        self.assertEqual(before,self.real_execution_inputs(api))

    def test_cache_hit_does_not_rewrite_the_complete_run_journal(self):
        record={'stages':{},'state':'running'}
        path=self.root/'knowledge/update-runs/fixture/run.json'
        journal=self.engine.Journal(self.api,self.workflow,self.args,record,path)
        journal.stage('one',{'input':'same'},lambda:{'state':'passed'})
        before=path.read_bytes()
        with patch.object(self.engine,'save',side_effect=AssertionError('Cached result must not rewrite the run')):
            cached=journal.stage('one',{'input':'same'},lambda:None)
        self.assertEqual(cached,{'state':'passed'})
        self.assertEqual(path.read_bytes(),before)

    def test_definition_change_creates_frozen_run_and_reuses_other_contract(self):
        import copy
        other=copy.deepcopy(self.contracts['contracts'][0]);other['id']='other'
        self.contracts['contracts'].append(other)
        path=self.knowledge/'update-contracts.json'
        path.write_text(json.dumps(self.contracts),'utf-8')
        def resolve(index,args,model,sha,discoveries):
            return dict(contracts={c['id']:dict(bindings={},queue=[]) for c in model['contracts']})
        with patch.object(self.bindings,'resolve',side_effect=resolve) as resolver, \
                patch.object(self.workflow,'run_checks',return_value=[dict(id='fixture-check',state='passed')]) as checks, \
                patch.object(self.update,'execute_adapter',return_value=dict(state='passed',result=dict(candidates=[]))) as discovery:
            first=self.engine.run(self.api,self.args,self.root/'knowledge/search.sqlite3')
            old=Path(first['run']).read_bytes();self.args.resume=Path(first['run'])
            self.contracts['contracts'][0]['recipes']=[dict(key='new',method='reviewed')]
            path.write_text(json.dumps(self.contracts),'utf-8')
            second=self.engine.run(self.api,self.args,self.root/'knowledge/search.sqlite3')
        self.assertNotEqual(first['run'],second['run'])
        self.assertEqual(Path(first['run']).read_bytes(),old)
        self.assertEqual(resolver.call_count,3)
        self.assertEqual(discovery.call_count,1)
        self.assertEqual(checks.call_count,2)  # Once per run, shared by both contracts.
        saved=self.engine.read(self.api,self.workflow,Path(second['run']),self.root)
        self.assertIn('fixture',saved['plan']['affected'])

    def test_unchanged_index_is_validated_without_starting_writer(self):
        first,_=self.run_fixture();self.args.resume=Path(first['run'])
        with patch.object(self.api,'build',side_effect=AssertionError('Unchanged index must not be rebuilt')):
            self.run_fixture()

    def test_unchanged_rejected_context_is_cached_without_another_native_attempt(self):
        self.contracts['contracts'][0]['context_checks']=['version-login-tag']
        (self.knowledge/'update-contracts.json').write_text(json.dumps(self.contracts),'utf-8')
        verifier=Mock(side_effect=ValueError('Fixture dependency is not yet closed'))
        self.modules['verify-version-login-context']=SimpleNamespace(verify=verifier)
        first,_=self.run_fixture();self.args.resume=Path(first['run'])
        second,_=self.run_fixture()
        self.assertEqual(verifier.call_count,1)
        self.assertEqual(second['metrics']['context_replays_this_run'],0)

    def test_resource_material_key_pins_baseline_and_referenced_blob(self):
        archive=self.root/'example.pak'
        entries=self.root/'pak-extracted/example/entries.json';entries.parent.mkdir(parents=True)
        blob=entries.parent/'blob.bin';blob.write_bytes(b'one')
        entries.write_text(json.dumps([dict(saved=str(blob))]),'utf-8')
        row=dict(path=str(archive),current=dict(sha256='a'*64,size=10,pak_version=11),
            baseline=dict(sha256='b'*64,size=10,pak_version=11))
        first=self.engine.resource_stage_inputs(self.api,self.args,row,{})
        row['current']['modified_ns']=100
        self.assertEqual(first,self.engine.resource_stage_inputs(self.api,self.args,row,{}))
        row['baseline']['sha256']='c'*64
        self.assertNotEqual(first,self.engine.resource_stage_inputs(self.api,self.args,row,{}))
        row['baseline']['sha256']='b'*64;blob.write_bytes(b'two')
        self.assertNotEqual(first,self.engine.resource_stage_inputs(self.api,self.args,row,{}))

    def test_equal_inventory_with_missing_required_artifacts_is_not_complete(self):
        contract=dict(self.contracts['contracts'][0],resources=[dict(archive='*.pak',path='*Quest*')])
        row=dict(path=str(self.pak),current=dict(sha256='a'*64,pak_version=11),baseline=dict(sha256='a'*64))
        result=self.engine.resource_work(self.api,self.args,dict(exe=dict(sha256=self.sha),files=[row]),
            dict(contracts=[contract]),[])
        self.assertEqual(result,[row])

    def test_shared_root_blocker_has_reverse_consumers_and_legacy_count(self):
        import copy
        second=copy.deepcopy(self.contracts['contracts'][0]);second.update(id='other',depends_on=['fixture'])
        contracts=dict(self.contracts,contracts=[self.contracts['contracts'][0],second],order=['fixture','other'])
        queue=[dict(contract='fixture',reason='shared-check: requires_port'),
            dict(contract='other',reason='shared-check: requires_port'),
            dict(contract='other',reason='Dependencies incomplete: fixture')]
        result=self.engine.root_blockers(contracts,{},queue)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]['contracts'],['fixture','other'])
        self.assertEqual(result[0]['observations'],2)

    def test_changed_check_affects_its_contract_and_reverse_consumers_only(self):
        import copy
        first=copy.deepcopy(self.contracts['contracts'][0])
        second=dict(copy.deepcopy(first),id='other',checks=[],depends_on=['fixture'])
        unrelated=dict(copy.deepcopy(first),id='unrelated',checks=['other-check'])
        contracts=dict(self.contracts,contracts=[first,second,unrelated],order=['fixture','other','unrelated'])
        old_checks=[dict(id='fixture-check'),dict(id='other-check')]
        checks=[dict(id='fixture-check',timeout_seconds=200),dict(id='other-check')]
        previous=dict(plan=dict(contracts=copy.deepcopy(contracts),checks={c['id']:c for c in old_checks},
            tools=self.tools,definition_sha256={'research-checks.json':'old'}))
        result=self.engine.affected_plan(self.model,contracts,checks,exe_changed=False,changes=[],
            previous=previous,definitions={'research-checks.json':'new'},tools=self.tools)
        self.assertEqual(result['affected'],['fixture','other'])

    def test_function_frontier_reports_intrinsic_roots_without_derived_callers(self):
        report=self.workflow.snapshot(self.root,'function-reuse-catalog',dict(dependency_frontier=[
            dict(source_sha256=self.sha,address='0x140001000',reasons=['dependency_not_declared'],direct_consumers=12,consumers=[]),
            dict(source_sha256=self.sha,address='0x140002000',reasons=['callee_not_closed: 0x140001000'],direct_consumers=2,consumers=[])]))
        result=self.engine.function_blockers(self.api,dict(report=str(report)),self.contracts)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]['direct_function_consumers'],12)
        self.assertFalse(result[0]['runtime_activated'])

    def test_resource_context_pins_only_declared_archive_dependencies(self):
        contract=dict(resources=[dict(archive='*quest.pak',path='Data/Quest*')])
        rows=[dict(path='quest.pak',current=dict(sha256='a'*64)),dict(path='other.pak',current=dict(sha256='b'*64))]
        before=self.engine.resource_inputs(contract,rows)
        rows[1]['current']['sha256']='c'*64
        self.assertEqual(before,self.engine.resource_inputs(contract,rows))
        rows[0]['current']['sha256']='d'*64
        self.assertNotEqual(before,self.engine.resource_inputs(contract,rows))
        self.assertFalse(before[0]['logical_paths_verified'])

    def test_export_batches_are_bounded_explicit_and_ready_exports_are_reused(self):
        at=['0x'+format(0x140001000+16*n,'x') for n in range(35)]
        context=dict(contracts={'fixture':dict(bindings={str(n):a for n,a in enumerate(at)})})
        journal=self.engine.Journal(self.api,self.workflow,self.args,dict(stages={}),
            self.root/'knowledge/update-runs/fixture/run.json')
        ready=set();calls=[]
        def function(index,db,sha,address):return dict(state='ready' if address in ready else 'missing',variants=[])
        def collect(index,args,request,batch):
            self.assertTrue(set(batch)<={f['address'] for f in request['functions']})
            self.assertLessEqual(len(batch),32)
            calls.append(batch[:]);ready.update(batch)
            return dict(state='collected',addresses=batch)
        with patch.object(self.api,'open_index',return_value=Mock()),patch.object(self.api,'build'), \
                patch.object(self.workflow,'function_state',side_effect=function), \
                patch.object(self.workflow,'collector',side_effect=collect):
            self.engine.collect_batches(self.api,self.workflow,journal,self.args,self.root/'db',context,self.sha)
            self.engine.collect_batches(self.api,self.workflow,journal,self.args,self.root/'db',context,self.sha)
        self.assertEqual([len(c) for c in calls],[32,3])

    def test_missing_required_check_blocks_capability(self):
        with patch.object(self.bindings,'resolve',return_value=dict(contracts={'fixture':dict(bindings={},queue=[])})), \
                patch.object(self.workflow,'run_checks',return_value=[dict(id='fixture-check',state='requires_port')]), \
                patch.object(self.update,'execute_adapter',return_value=dict(state='passed',result=dict(candidates=[]))):
            result=self.engine.run(self.api,self.args,self.root/'knowledge/search.sqlite3')
        self.assertEqual(result['capabilities']['fixture']['state'],'incomplete')
        self.assertEqual(result['profiles'],[])

    def test_profile_failure_does_not_poison_cached_contract_on_resume(self):
        self.contracts['contracts'][0]['builder']='sdk-launcher'
        self.contracts['order']=['fixture']
        self.modules['update-profile']=SimpleNamespace(inputs=Mock(return_value=dict(selected='fixture')))
        profile=self.workflow.snapshot(self.root,'prepared-profiles',dict(activated=False))
        with patch.object(self.model,'load',return_value=self.contracts), \
                patch.object(self.engine,'build_profile',side_effect=ValueError('Missing report')):
            first,_=self.run_fixture()
        self.assertEqual(first['capabilities']['fixture']['state'],'incomplete')
        saved=self.engine.read(self.api,self.workflow,Path(first['run']),self.root)
        self.assertEqual(saved['stages']['contract-fixture']['result']['state'],'passed')
        self.args.resume=Path(first['run'])
        with patch.object(self.model,'load',return_value=self.contracts), \
                patch.object(self.engine,'build_profile',return_value=dict(profile=str(profile),activated=False)):
            resumed,_=self.run_fixture()
        self.assertEqual(resumed['capabilities']['fixture']['state'],'prepared_offline')

    def test_unassigned_on_update_check_is_preserved_in_manual_queue(self):
        path=self.knowledge/'research-checks.json'
        path.write_text(json.dumps(dict(checks=[dict(id='fixture-check'),dict(id='extra',on_update=True)])),'utf-8')
        def check(index,args,sha,question,*,check_ids):
            return [dict(id=check_ids[0],state='requires_port' if check_ids==['extra'] else 'passed')]
        with patch.object(self.bindings,'resolve',return_value=dict(contracts={'fixture':dict(bindings={},queue=[])})), \
             patch.object(self.workflow,'run_checks',side_effect=check) as checks, \
             patch.object(self.update,'execute_adapter',return_value=dict(state='passed',result=dict(candidates=[]))):
            result=self.engine.run(self.api,self.args,self.root/'knowledge/search.sqlite3')
        self.assertEqual(checks.call_count,2)
        saved=self.engine.read(self.api,self.workflow,Path(result['run']),self.root)
        self.assertTrue(any(q['reason']=='extra: requires_port' for q in saved['queue']))
        self.assertEqual(result['capabilities']['fixture']['state'],'prepared_offline')

    def test_failure_outside_stage_keeps_reason_and_completed_work(self):
        with patch.object(self.bindings,'resolve',return_value=dict(contracts={'fixture':dict(bindings={},queue=[])})), \
             patch.object(self.update,'execute_adapter',return_value=dict(state='passed',result=dict(candidates=[]))), \
             patch.object(self.api,'build',side_effect=ValueError('Index fixture failure')):
            with self.assertRaisesRegex(ValueError,'Index fixture failure'):
                self.engine.run(self.api,self.args,self.root/'knowledge/search.sqlite3')
        paths=list((self.root/'knowledge/update-runs').glob('*/run.json'))
        self.assertEqual(len(paths),1)
        saved=self.engine.read(self.api,self.workflow,paths[0],self.root)
        self.assertEqual(saved['state'],'failed');self.assertEqual(saved['reason'],'Index fixture failure')
        self.assertEqual(saved['stages']['bindings']['state'],'completed')


# unittest would otherwise rerun all tests inherited from the fixture class.
for _name in dir(fixture.ResearchUpdateTests):
    if _name.startswith('test_') and _name not in UpdateRunTests.__dict__:
        setattr(UpdateRunTests,_name,None)

def load_tests(loader, tests, pattern):
    suite=loader.loadTestsFromTestCase(UpdateRunTests)
    suite.addTests(loader.loadTestsFromName('test_vampir_update_source_store'))
    suite.addTests(loader.loadTestsFromName('test_vampir_update_archive_selection'))
    return suite


if __name__ == '__main__': unittest.main()
