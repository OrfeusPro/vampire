"""Полный fixture-контроллер: проекция, кэш и барьер до publication."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

import test_vampir_update_run as parent


class ProjectionRoutingTests(parent.UpdateRunTests):
    def setUp(self):
        super().setUp()
        self.events=[];self.actions=[];self.observed=[];self.fail_finish=False
        self.projection_rule='fixture-v1'
        contract=self.contracts['contracts'][0]
        contract.update(id='game-version',coverage='partial',context_checks=['version-login-tag','packet-writer-projection'])
        self.contracts['capabilities']={'fixture':dict(requires=['game-version'])}
        (self.knowledge/'update-contracts.json').write_text(json.dumps(self.contracts),'utf-8')
        (self.knowledge/'contract-projections.json').write_text('{}','utf-8')
        outer=self
        class Projection:
            def prepare(self,*_):outer.events.append('projection_prepare')
            def project(self,context):
                result=copy.deepcopy(context);result['bindings']['queue']=[]
                result['projection']={'source':'fixture-publication'}
                return result
            def inputs(self,context,adapter):return dict(rule=outer.projection_rule,adapter=adapter)
            def check(self,context,adapter):
                outer.actions.append(adapter)
                value=dict(state='requires_review' if adapter=='version-login-tag' else 'passed',
                    reason='wrapper_constructor_current_provider_missing' if adapter=='version-login-tag' else '')
                path=outer.workflow.snapshot(outer.root,'projection-fixtures',dict(value,adapter=adapter))
                return dict(value,id=adapter,report=str(path),sha256=outer.api.digest(path))
            def observe(self,context,adapter,result):outer.observed.append(adapter)
            def finish(self):
                outer.events.append('projection_finish')
                if outer.fail_finish:raise ValueError('late projection input changed')
                return {'owner_barrier_completed':True}
        self.modules['contract-projections-v1']=SimpleNamespace(enabled=lambda *_:True,begin=lambda *_:Projection())
        def prepare(*_):
            self.events.append('bundle_prepare')
            return dict(bundles=[],next_profiles={},queue=[],live_verified=False)
        def publish(index,args,result,**kwargs):self.events.append('bundle_publish');return result
        self.modules['update-bundle']=SimpleNamespace(prepare=prepare,publish=publish)
        for name in ('verify-version-login-context','verify-packet-writer-context'):
            self.modules[name]=SimpleNamespace(verify=Mock(side_effect=AssertionError('Legacy native suite must not run')))

    def projected_run(self):
        with patch.object(self.bindings,'resolve',return_value=dict(contracts={'game-version':dict(bindings={},queue=['constructor: missing candidate'])})),\
                patch.object(self.workflow,'run_checks',return_value=[dict(id='fixture-check',state='passed')]),\
                patch.object(self.update,'execute_adapter',return_value=dict(state='passed',result=dict(candidates=[]))):
            return self.engine.run(self.api,self.args,self.root/'knowledge/search.sqlite3')

    def test_projected_checks_reuse_cache_and_preserve_real_blocker(self):
        first=self.projected_run()
        self.args.resume=Path(first['run']);self.projected_run()
        self.assertEqual(self.actions,['version-login-tag','packet-writer-projection'])
        self.assertEqual(len(self.observed),4)
        journal=self.engine.read(self.api,self.workflow,Path(first['run']),self.root)
        outcome=journal['stages']['contract-game-version']['result']
        text=str(outcome)
        self.assertIn('wrapper_constructor_current_provider_missing',text)
        self.assertNotIn('constructor: missing candidate',text)
        self.assertEqual(first['state'],'needs_review')
        self.assertFalse(journal['capabilities']['fixture']['live_verified'])

    def test_projection_barrier_precedes_bundle_publication(self):
        self.projected_run()
        self.assertLess(self.events.index('bundle_prepare'),self.events.index('projection_finish'))
        self.assertLess(self.events.index('projection_finish'),self.events.index('bundle_publish'))

    def test_late_projection_change_blocks_publication(self):
        self.fail_finish=True
        with self.assertRaisesRegex(ValueError,'late projection input changed'):self.projected_run()
        self.assertNotIn('bundle_publish',self.events)

    def test_projected_cache_ignores_unrelated_context_tools_but_rechecks_own_rule(self):
        first=self.projected_run()
        self.args.resume=Path(first['run'])
        self.tools['context']['unrelated-suite']='changed'
        self.projected_run()
        self.assertEqual(len(self.actions),2)
        self.projection_rule='fixture-v2'
        self.projected_run()
        self.assertEqual(len(self.actions),4)


def load_tests(loader,tests,pattern):
    # Reuse the factory, not all inherited unchanged controller test methods.
    names=('test_projected_checks_reuse_cache_and_preserve_real_blocker',
        'test_projection_barrier_precedes_bundle_publication','test_late_projection_change_blocks_publication',
        'test_projected_cache_ignores_unrelated_context_tools_but_rechecks_own_rule')
    return unittest.TestSuite(ProjectionRoutingTests(name) for name in names)


if __name__=='__main__':unittest.main()
