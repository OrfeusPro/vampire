"""Static quest-reader preparation preserves provenance and semantic boundaries."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from test_vampir_update_contracts import load
import test_vampir_quest_input_seed_v2 as seed_fixtures

READER=load('quest-reader-transfer-v1')
SEED=seed_fixtures.SEED
WORKFLOW=seed_fixtures.WORKFLOW


class QuestReaderTransferTests(unittest.TestCase):
    def setUp(self):
        f=seed_fixtures.QuestInputSeedTests();f.setUp();self.addCleanup(f.doCleanups);self.f=f
        self.root,self.args,self.index=f.root,f.args,f.index
        self.sha=f.sha;self.seed=f.run_seed()
        self.selector=f.knowledge/'quest-reader-transfer.json'
        self.selector.write_bytes(WORKFLOW.canonical(dict(schema=1,recipe='quest-reader-transfer-v1')))
        self.journal=seed_fixtures.Journal()
        self.rule_file=self.root/'reader-rules.py';self.rule_file.write_bytes(b'synthetic whole reader transfer rules')
        self.store=f.store;self.store.index=self.index
        self.package=dict(counts=dict(seed_roots=7,transferred_roots=15,total_roots=22),
            target_source_sha256=self.sha,target_contexts={name:dict(source_sha256=self.sha,
                functions={role:hex(int(at,16)+0x10000) for role,at in context['functions'].items()})
                for name,context in f.consumers.items()},native_consumer_verified=False,runtime_activated=False,profile_activated=False)
        self.rules=SimpleNamespace(tools=lambda:{str(self.rule_file):seed_fixtures.digest(self.rule_file)},
            transfer=Mock(side_effect=lambda *a:copy.deepcopy(self.package)),validate_package=self.validate_package)
        self.base_extension=self.index.extension;self.index.extension=self.extension

    def validate_package(self,package,inputs):
        if (set(package)!=set(self.package) or package['counts']!=dict(seed_roots=7,transferred_roots=15,total_roots=22)
                or package['target_source_sha256']!=inputs['target_source_sha256']
                or set(package['target_contexts'])!={'quest-sync','tutorial-update'}
                or any(context['source_sha256']!=inputs['target_source_sha256'] for context in package['target_contexts'].values())
                or any(package[k] is not False for k in ('native_consumer_verified','runtime_activated','profile_activated'))):
            raise ValueError('Synthetic transferred package source/scope/counts differ')

    def extension(self,name):
        if name=='quest-input-seed-v2':return SEED
        if name=='quest-reader-transfer-rules-v1':return self.rules
        return self.base_extension(name)

    def run_reader(self,seed=None):
        return READER.run(self.index,self.args,self.sha,self.journal,self.seed if seed is None else seed)

    def test_missing_seed_is_a_concrete_blocker_without_a_transfer(self):
        result=self.run_reader(dict(state='requires_review',reason='version_result_target_missing'))
        self.assertEqual(result['state'],'requires_review');self.assertTrue(result['reason'])
        self.rules.transfer.assert_not_called();self.assertEqual(self.journal.actions,0)

    def test_corrupt_seed_proof_is_not_recovered_by_a_new_native_run(self):
        Path(self.seed['report']).write_bytes(b'corrupt seed evidence')
        result=self.run_reader()
        self.assertEqual(result['state'],'requires_review');self.rules.transfer.assert_not_called()

    def test_replacing_source_store_rejects_the_seed_invocation_identity(self):
        self.args.source_store=copy.copy(self.args.source_store)
        result=self.run_reader()
        self.assertEqual(result['state'],'requires_review');self.rules.transfer.assert_not_called()

    def test_seed_from_another_target_is_not_accepted_by_its_old_source_roles(self):
        self.sha=self.f.old_sha
        result=self.run_reader()
        self.assertEqual(result['state'],'requires_review');self.rules.transfer.assert_not_called()

    def test_unknown_transfer_rule_is_not_inferred(self):
        self.selector.write_bytes(WORKFLOW.canonical(dict(schema=1,recipe='unreviewed-quest-rules')))
        with self.assertRaises(ValueError):self.run_reader()
        self.rules.transfer.assert_not_called()

    def test_complete_static_result_keeps_semantic_and_runtime_admission_open(self):
        result=self.run_reader()
        self.assertEqual((result['state'],result['method']),('prepared_static','static'))
        self.assertEqual(result['counts'],dict(seed_roots=7,transferred_roots=15,total_roots=22))
        for key in ('native_consumer_verified','runtime_activated','profile_activated','final_validation_completed'):
            self.assertIs(result[key],False)
        self.assertTrue(result['final_validation_pending'])
        self.assertEqual(len(self.f.native_contexts['checks']),1);self.assertEqual(len(self.f.native_checks),1)

    def test_warm_repeat_uses_the_same_proof_without_transfer_or_pe_reads(self):
        first=self.run_reader();images=self.store.image.call_count
        second=self.run_reader()
        self.assertEqual(second,first);self.rules.transfer.assert_called_once()
        self.assertEqual(self.store.image.call_count,images);self.assertEqual(self.journal.actions,1)

    def test_static_rule_failure_becomes_a_concrete_blocker(self):
        self.rules.transfer.side_effect=ValueError('ambiguous consumer callback root')
        result=self.run_reader()
        self.assertEqual(result['state'],'requires_review');self.assertIn('ambiguous consumer callback',result['reason'])
        self.assertFalse(list((self.root/'knowledge'/READER.CATEGORY).glob('*/manifest.json')))

    def test_corrupt_cached_proof_cannot_trigger_a_silent_rebuild(self):
        first=self.run_reader();Path(first['report']).write_bytes(b'corrupt reader transfer evidence')
        result=self.run_reader()
        self.assertEqual(result['state'],'requires_review');self.rules.transfer.assert_called_once()

    def test_freshly_hashed_cache_proof_cannot_change_the_static_scope(self):
        first=self.run_reader();proof=json.loads(Path(first['report']).read_bytes())
        proof['native_consumer_verified']=True;pointer=self.f.snapshot(READER.CATEGORY,proof)
        key=next(iter(self.journal.values));cached=self.journal.values[key]
        cached.update(proof=pointer,report=pointer['path'],sha256=pointer['sha256'],native_consumer_verified=True)
        self.assertEqual(self.run_reader()['state'],'requires_review');self.rules.transfer.assert_called_once()

    def test_newly_hashed_package_with_different_counts_is_rejected(self):
        first=self.run_reader();proof=json.loads(Path(first['report']).read_bytes())
        proof['package']['counts']['transferred_roots']=14;pointer=self.f.snapshot(READER.CATEGORY,proof)
        key=next(iter(self.journal.values));self.journal.values[key].update(proof=pointer,report=pointer['path'],
            sha256=pointer['sha256'],counts=proof['package']['counts'])
        self.assertEqual(self.run_reader()['state'],'requires_review');self.rules.transfer.assert_called_once()

    def test_changed_reader_rules_invalidate_an_unchanged_seed(self):
        first=self.run_reader();self.rule_file.write_bytes(b'new reviewed synthetic reader rules')
        second=self.run_reader()
        self.assertEqual(second['state'],'prepared_static');self.assertNotEqual(first['proof'],second['proof'])
        self.assertEqual(self.rules.transfer.call_count,2)

    def test_changed_runtime_invalidates_the_static_transfer_key(self):
        first=self.run_reader();self.f.runtime['portable']='new current runtime'
        second=self.run_reader()
        self.assertEqual(second['state'],'prepared_static');self.assertNotEqual(first['proof'],second['proof'])
        self.assertEqual(self.rules.transfer.call_count,2)

    def test_changed_binary_runtime_invalidates_the_static_transfer_key(self):
        first=self.run_reader();self.f.runtime_file.write_bytes(b'new runtime fixture binary')
        second=self.run_reader()
        self.assertEqual(second['state'],'prepared_static');self.assertNotEqual(first['proof'],second['proof'])
        self.assertEqual(self.rules.transfer.call_count,2)

    def test_selector_drift_during_transfer_blocks_the_result(self):
        def transfer(*args):
            self.selector.write_bytes(WORKFLOW.canonical(dict(schema=1,recipe='quest-reader-transfer-v1',unexpected=True)))
            return copy.deepcopy(self.package)
        self.rules.transfer.side_effect=transfer
        result=self.run_reader()
        self.assertEqual(result['state'],'requires_review');self.assertIn('changed',result['reason'])

    def test_late_input_or_proof_mutation_blocks_the_final_barrier(self):
        for kind in ('rule','proof'):
            with self.subTest(kind=kind):
                self.setUp();result=self.run_reader()
                path=self.rule_file if kind=='rule' else Path(result['report'])
                path.write_bytes(path.read_bytes()+b'!')
                with self.assertRaises(ValueError):READER.finalize(self.index,self.args,result)
                self.assertFalse(result['final_validation_completed'])

    def test_final_validation_needs_the_original_finished_scoped_owner(self):
        owner=SimpleNamespace(closed=False,finished=False)
        self.args._scope_v2_state=dict(owner=owner,source_store=self.store)
        self.args._quest_input_seed_v2_state['owner']=owner
        result=self.run_reader()
        with self.assertRaises(ValueError):READER.finalize(self.index,self.args,result)
        owner.finished=True
        final=READER.finalize(self.index,self.args,result)
        self.assertTrue(final['final_validation_completed']);self.assertFalse(final['final_validation_pending'])
        self.assertFalse(final['native_consumer_verified']);self.rules.transfer.assert_called_once()

    def test_replacing_owner_after_static_transfer_cannot_complete_final_validation(self):
        owner=SimpleNamespace(closed=False,finished=True)
        self.args._scope_v2_state=dict(owner=owner,source_store=self.store)
        self.args._quest_input_seed_v2_state['owner']=owner
        result=self.run_reader()
        self.args._scope_v2_state['owner']=SimpleNamespace(finished=True)
        with self.assertRaises(ValueError):READER.finalize(self.index,self.args,result)

    def test_seed_invocation_owner_cannot_be_replaced_before_transfer(self):
        self.args._scope_v2_state=dict(owner=SimpleNamespace(closed=False,finished=False),source_store=self.store)
        result=self.run_reader()
        self.assertEqual(result['state'],'requires_review');self.rules.transfer.assert_not_called()

    def test_replacing_source_store_after_transfer_blocks_final_validation(self):
        result=self.run_reader();self.args.source_store=copy.copy(self.store)
        with self.assertRaises(ValueError):READER.finalize(self.index,self.args,result)


if __name__=='__main__':unittest.main()
