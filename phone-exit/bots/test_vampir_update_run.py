import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_vampir_research_update as fixture


class UpdateRunTests(fixture.ResearchUpdateTests):
    # Reuse the synthetic installation factory, not its inherited test methods.
    def setUp(self):
        super().setUp()
        self.engine = self.index.extension('update-run')
        self.model = self.index.extension('update-contracts')
        self.bindings = self.index.extension('update-bindings')
        self.modules = {'research-workflow':self.workflow,'research-update':self.update,
            'update-run':self.engine,'update-contracts':self.model,'update-bindings':self.bindings}
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
        before=self.engine.execution_inputs(self.api)
        original=self.api.digest
        def digest(path):return '0'*64 if Path(path).resolve()==(self.index.HERE/'update-profile.py').resolve() else original(path)
        with patch.object(self.api,'digest',side_effect=digest):after=self.engine.execution_inputs(self.api)
        self.assertEqual(before['resources'],after['resources'])
        self.assertEqual(before['discovery'],after['discovery'])
        self.assertNotEqual(before['profile'],after['profile'])

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

if __name__ == '__main__': unittest.main()
