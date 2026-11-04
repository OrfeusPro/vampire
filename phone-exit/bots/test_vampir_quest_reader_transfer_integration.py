"""Ordinary update wires static packet transfer after INPUT seed and before publish."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import test_vampir_quest_input_seed_integration as fixture


class QuestReaderTransferIntegration(unittest.TestCase):
    def setUp(self):
        self.seed_fixture=fixture.QuestInputSeedIntegration('runTest');self.seed_fixture.setUp()
        self.addCleanup(self.seed_fixture.doCleanups)
        self.f=self.seed_fixture.f;self.events=self.seed_fixture.events
        (self.f.knowledge/'quest-reader-transfer.json').write_text('{}',encoding='utf-8')
        self.result=dict(state='prepared_static',counts=dict(seed_roots=7,transferred_roots=15,total_roots=22),
            native_consumer_verified=False,runtime_activated=False,profile_activated=False)
        def run(*args):
            self.events.append('reader-transfer');return copy.deepcopy(self.result)
        def finalize(index,args,result):
            self.events.append('reader-finalize');return dict(result,final_validation_completed=True)
        self.run=Mock(side_effect=run);self.finalize=Mock(side_effect=finalize)
        self.f.modules['quest-reader-transfer-v1']=SimpleNamespace(run=self.run,finalize=self.finalize)

    def fixture_run(self):
        result,_=self.f.run_fixture()
        return result,json.loads(Path(result['run']).read_bytes())['payload']

    def test_seed_and_packet_stage_finish_in_order_without_native_admission(self):
        result,record=self.fixture_run()
        self.assertEqual(self.events,['driver','seed','reader-transfer','finalize','reader-finalize'])
        self.assertEqual(self.run.call_args.args[4],self.seed_fixture.seed)
        self.assertEqual(record['quest_reader_transfer'],dict(self.result,final_validation_completed=True))
        self.assertEqual(record['native_checks'],[self.seed_fixture.check])
        self.assertEqual(record['native_contexts']['checks'],[self.seed_fixture.declaration])
        self.assertFalse(result['profile_activation'])

    def test_transfer_blocker_is_concrete_and_does_not_promote_quests(self):
        self.result.update(state='requires_review',reason='Packet ID table ambiguous')
        result,record=self.fixture_run()
        blockers=[q for q in record['queue'] if q.get('reason')=='quest_reader_transfer_requires_review']
        self.assertEqual(len(blockers),1)
        self.assertEqual(blockers[0]['evidence'],self.result)
        self.assertEqual(result['state'],'needs_review')
        self.assertFalse(result['profile_activation'])

    def test_final_transfer_guard_failure_prevents_bundle_publication(self):
        publish=Mock(return_value=dict(queue=[]));self.f.modules['update-bundle'].publish=publish
        self.finalize.side_effect=ValueError('Reader transfer artifact changed')
        with self.assertRaisesRegex(ValueError,'Reader transfer artifact changed'):self.fixture_run()
        publish.assert_not_called()

    def test_missing_selector_skips_transfer_only(self):
        (self.f.knowledge/'quest-reader-transfer.json').unlink()
        _,record=self.fixture_run()
        self.run.assert_not_called();self.finalize.assert_not_called()
        self.assertIn('quest_input_seed',record);self.assertNotIn('quest_reader_transfer',record)

    def test_plan_only_starts_neither_seed_nor_transfer(self):
        self.f.args.plan_only=True
        result,_=self.fixture_run()
        self.assertEqual(result['state'],'planned');self.assertEqual(self.events,[])


if __name__=='__main__':unittest.main()
