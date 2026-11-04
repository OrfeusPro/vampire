"""Ordinary updater reaches the static seed without changing native admission."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import test_vampir_update_run as fixture


class QuestInputSeedIntegration(unittest.TestCase):
    def setUp(self):
        self.f=fixture.UpdateRunTests('runTest');self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.events=[]
        self.declaration=dict(id='native-auto-version-result',family='version-result',context=dict(path='fixture-context',sha256='a'*64))
        self.check=dict(id='native-auto-version-result',state='passed',report='fixture-proof',sha256='b'*64)
        native=SimpleNamespace(operational_model=lambda i,a,m:m,
            materialize=Mock(return_value=dict(checks=[],queue=[],state='materialized')))
        self.f.modules['update-native-contexts']=native
        def run(*args):
            self.events.append('driver')
            return dict(declarations=[copy.deepcopy(self.declaration)],checks=[copy.deepcopy(self.check)],queue=[])
        def merge(contexts,checks,extra):
            contexts['checks'].extend(extra['declarations']);checks.extend(extra['checks'])
        self.f.modules['update-native-drivers']=SimpleNamespace(run=run,merge=merge)
        self.seed=dict(state='prepared_static',mapped_roots=7,consumer_semantic_verified=False,
            runtime_activated=False,profile_activated=False)
        def seed(*args):
            self.events.append('seed');return copy.deepcopy(self.seed)
        self.hook=Mock(side_effect=seed)
        def finalize(index,args,result):
            self.events.append('finalize');return dict(result,final_validation_completed=True)
        self.finalize=Mock(side_effect=finalize)
        self.f.modules['quest-input-seed-v2']=SimpleNamespace(run=self.hook,finalize=self.finalize)
        for name in ('native-release-registry.json','native-check-adapters.json','quest-input-seed.json'):
            (self.f.knowledge/name).write_text('{}',encoding='utf-8')

    def run_fixture(self):
        result,_=self.f.run_fixture()
        record=json.loads(Path(result['run']).read_bytes())['payload']
        return result,record

    def test_completed_driver_supplies_target_before_static_seed(self):
        result,record=self.run_fixture()
        self.assertEqual(self.events,['driver','seed','finalize'])
        args=self.hook.call_args.args
        self.assertEqual(args[2],self.f.sha)
        self.assertEqual(args[4]['checks'],[self.declaration])
        self.assertEqual(args[5],[self.check])
        self.assertEqual(record['quest_input_seed'],dict(self.seed,final_validation_completed=True))
        self.assertEqual(record['native_checks'],[self.check])
        self.assertEqual(record['native_contexts']['checks'],[self.declaration])
        self.assertFalse(result['profile_activation'])
        self.assertFalse(any(q.get('reason')=='quest_input_seed_requires_review' for q in record['queue']))

    def test_missing_target_is_exposed_as_one_concrete_blocker(self):
        self.seed.update(state='requires_review',reasons=['target_version_result_missing'])
        result,record=self.run_fixture()
        blockers=[q for q in record['queue'] if q.get('reason')=='quest_input_seed_requires_review']
        self.assertEqual(len(blockers),1)
        self.assertEqual(blockers[0]['evidence'],self.seed)
        self.assertEqual(result['state'],'needs_review')
        self.assertFalse(result['profile_activation'])

    def test_absent_selector_keeps_optional_hook_inactive(self):
        (self.f.knowledge/'quest-input-seed.json').unlink()
        _,record=self.run_fixture()
        self.hook.assert_not_called()
        self.finalize.assert_not_called()
        self.assertNotIn('quest_input_seed',record)

    def test_plan_only_does_not_prepare_seed_or_start_driver(self):
        self.f.args.plan_only=True
        result,_=self.run_fixture()
        self.assertEqual(result['state'],'planned')
        self.assertEqual(self.events,[])

    def test_final_seed_guard_failure_prevents_bundle_publication(self):
        publisher=Mock(return_value=dict(bundles=[],queue=[]))
        self.f.modules['update-bundle'].publish=publisher
        self.finalize.side_effect=ValueError('Seed proof changed after preparation')
        with self.assertRaisesRegex(ValueError,'Seed proof changed'):
            self.run_fixture()
        publisher.assert_not_called()


if __name__=='__main__':unittest.main()
