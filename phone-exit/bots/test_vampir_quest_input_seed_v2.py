"""Shared INPUT preparation preserves consumer gaps and checks cached evidence."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from test_vampir_update_contracts import load

SEED=load('quest-input-seed-v2')
WORKFLOW=load('research-workflow')


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Journal:
    def __init__(self):self.values={};self.inputs=[];self.actions=0
    def stage(self,name,inputs,action):
        self.inputs.append(copy.deepcopy(inputs))
        key=(name,WORKFLOW.canonical(inputs))
        if key not in self.values:
            self.actions+=1;self.values[key]=copy.deepcopy(action())
        return copy.deepcopy(self.values[key])


class QuestInputSeedTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve();self.here=self.root/'tools';self.knowledge=self.here/'knowledge'
        (self.knowledge/'native-contexts').mkdir(parents=True)
        self.old_sha=self.client(b'old synthetic public PE');self.sha=self.client(b'target synthetic public PE')
        self.role_map=dict(input_constructor='constructor',input_buffer_constructor='buffer_constructor',input_u16='u16',
            input_u32='u32',input_u64='u64',input_bool='bool',input_raw='raw')
        old_roles={v:hex(0x140001000+i*0x100) for i,v in enumerate(self.role_map.values())}
        target_roles={k:hex(int(v,16)+0x10000) for k,v in old_roles.items()}
        old_roles.update({k:hex(0x140003000+i*0x100) for i,k in enumerate(('time','string','std_string','utf8_length','utf8_convert','utf8_core','utf8_scalar'))})
        target_roles.update({k:hex(int(v,16)+0x10000) for k,v in old_roles.items() if k not in target_roles})
        self.old=dict(source_sha256=self.old_sha,source=str(self.source(self.old_sha)),reader='0x140004000',
            native_input=dict(source_sha256=self.old_sha,functions=old_roles,table='0x140010000',
                buffer_construction=dict(base_table='0x140010100',reading_mode=1,reading_endian=0)))
        self.target=copy.deepcopy(self.old);self.target.update(source_sha256=self.sha,source=str(self.source(self.sha)),family='version-result')
        self.target['native_input'].update(source_sha256=self.sha,functions=target_roles)
        shared={k:old_roles[v] for k,v in self.role_map.items()};shared.update(vector='0x140005000',reader='0x140005100')
        quest_private=('packet_constructor','nested_reader','group_reader','quest_reader','progress_reader',
            'group_callback','quest_callback','group_reserve','quest_reserve')
        tutorial_private=('packet_constructor','nested_reader','item_reader','callback')
        self.consumers={
            'quest-sync':dict(source_sha256=self.old_sha,functions={**shared,**{k:hex(0x140006000+i*0x100) for i,k in enumerate(quest_private)}}),
            'tutorial-update':dict(source_sha256=self.old_sha,functions={**shared,**{k:hex(0x140008000+i*0x100) for i,k in enumerate(tutorial_private)}})}
        self.baseline=self.context('version-result-fixture.json',self.old)
        self.consumer_ptrs={k:self.context(k+'-fixture.json',v) for k,v in self.consumers.items()}
        self.target['transfer_proof']=self.snapshot('native-version-result-proofs',dict(recipe='synthetic transferred input'))
        self.target_pointer=self.snapshot('generated-native-contexts',self.target)
        self.report=dict(source_sha256=self.sha,scope='bounded_native_version_result_input',method='bounded_native',
            context_sha256=self.target_pointer['sha256'],proof=self.target['transfer_proof'],network_used=False,
            profile_activated=False,runtime_activated=False)
        self.check_pointer=self.snapshot('native-adapter-checks',self.report)
        self.tool_file=self.root/'fixture-tool.py';self.tool_file.write_bytes(b'fixture version result rules')
        self.runtime_file=self.root/'fixture-runtime.dll';self.runtime_file.write_bytes(b'fixture runtime binary')
        self.runtime=dict(portable='runtime fixture 1');self.lineage_extra=self.root/'lineage.json';self.lineage_extra.write_bytes(b'{}')
        self.api=SimpleNamespace(tools=lambda:{str(self.tool_file):digest(self.tool_file)},ADAPTER='version-result-v1',SCOPE='bounded_native_version_result_input',
            plain=lambda c:{k:copy.deepcopy(v) for k,v in c.items() if k not in ('transfer_proof','exports','release_id')},
            validate=Mock(),export_coverage=Mock(),report_valid=Mock())
        relation=dict(mapping={a:b for a,b in zip(old_roles.values(),target_roles.values())})
        self.api.transfer=Mock(side_effect=lambda *a:(copy.deepcopy(self.target),copy.deepcopy(relation)))
        self.core=SimpleNamespace(digest=digest,pointer=self.pointer,checked=self.checked,lineage_inputs=self.lineage)
        self.store=SimpleNamespace(source=Mock(side_effect=self.source),digest=digest,
            image=Mock(side_effect=lambda native,sha:SimpleNamespace(sha=sha)),validate=Mock())
        self.args=SimpleNamespace(root=self.root,knowledge=self.knowledge,source_store=self.store)
        self.index=SimpleNamespace(HERE=self.here,digest=digest,extension=self.extension)
        self.journal=Journal();self.selector=self.knowledge/'quest-input-seed.json'
        self.rule=dict(schema=1,recipe='quest-input-seed-v2',version_baseline=self.baseline,consumers=self.consumer_ptrs)
        self.write_rule();self.declarations();self.calls=[]

    def source(self,sha):return self.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'

    def client(self,raw):
        sha=hashlib.sha256(raw).hexdigest();p=self.source(sha);p.parent.mkdir(parents=True);p.write_bytes(raw);return sha

    def pointer(self,path):return dict(path=str(path),sha256=digest(path))

    def context(self,name,body):
        p=self.knowledge/'native-contexts'/name;p.write_bytes(WORKFLOW.canonical(body));return self.pointer(p)

    def snapshot(self,category,body):return self.pointer(WORKFLOW.snapshot(self.root,category,body))

    def write_rule(self):self.selector.write_bytes(WORKFLOW.canonical(self.rule))

    def checked(self,root,pointer,category):
        path=Path(pointer['path']).resolve()
        if not path.is_relative_to(Path(root)/'knowledge'/category) or digest(path)!=pointer['sha256']:
            raise ValueError('Synthetic checked pointer changed')
        return json.loads(path.read_bytes())

    def lineage(self,args,path):
        result={str(Path(path).resolve()):digest(path),str(self.lineage_extra):digest(self.lineage_extra)}
        def walk(value):
            if isinstance(value,dict):
                if set(value)=={'path','sha256'}:
                    if digest(value['path'])!=value['sha256']:raise ValueError('Synthetic lineage changed')
                    result[value['path']]=value['sha256'];walk(json.loads(Path(value['path']).read_bytes()))
                else:
                    for child in value.values():walk(child)
            elif isinstance(value,list):
                for child in value:walk(child)
        walk(json.loads(Path(path).read_bytes()));return result

    def extension(self,name):
        return {'research-workflow':WORKFLOW,'portable-native-family':self.core,'update-native-version-result':self.api,
            'build-native-entry-code':SimpleNamespace(),'update-bindings':SimpleNamespace(),
            'stage-action-tools-v1':SimpleNamespace(runtime=lambda index:copy.deepcopy(self.runtime)),
            'update-native-harness':SimpleNamespace(runtime_inputs=lambda:dict(fixture='native runtime')),
            'native-publication-v2':SimpleNamespace(runtime_files=lambda:[self.runtime_file])}[name]

    def declarations(self):
        self.native_contexts=dict(checks=[dict(id='native-auto-version-result',adapter='version-result-v1',family='version-result',
            scope='bounded_native_version_result_input',context=self.target_pointer,proof=self.target['transfer_proof'],
            dependencies=self.api.tools(),artifacts={self.target_pointer['path']:self.target_pointer['sha256']})],queue=[])
        self.native_checks=[dict(id='native-auto-version-result',state='passed',report=self.check_pointer['path'],
            sha256=self.check_pointer['sha256'],scope='bounded_native_version_result_input',runtime_activated=False,profile_activated=False)]

    def run_seed(self):return SEED.run(self.index,self.args,self.sha,self.journal,self.native_contexts,self.native_checks)

    def test_shared_seed_preserves_the_unverified_consumer_closure(self):
        result=self.run_seed()
        self.assertEqual(result['state'],'prepared_static');self.assertEqual(result['method'],'static')
        self.assertEqual(len(result['mappings']),7)
        self.assertEqual({(row['role'],row['baseline'],row['target']) for row in result['mappings']},
            {(role,self.old['native_input']['functions'][role],self.target['native_input']['functions'][role])
                for role in self.role_map.values()})
        self.assertEqual(result['inventory']['unique_roots'],22)
        self.assertEqual(result['inventory']['shared_roots'],9)
        self.assertEqual(result['inventory']['pending_roots'],15)
        for key in ('native_consumer_verified','runtime_activated','profile_activated'):
            self.assertIs(result[key],False)
        self.assertEqual(len(self.native_contexts['checks']),1)
        self.assertEqual(len(self.native_checks),1)
        inputs=self.journal.inputs[-1]
        self.assertEqual(inputs['baseline'],dict(context=self.baseline,source_sha256=self.old_sha))
        self.assertEqual(inputs['target'],dict(context=self.target_pointer,source_sha256=self.sha,semantic_check=self.check_pointer))

    def test_warm_repeat_reuses_the_exact_static_proof_without_transfer(self):
        first=self.run_seed();second=self.run_seed()
        self.assertEqual((second['report'],second['sha256']),(first['report'],first['sha256']))
        self.api.transfer.assert_called_once();self.assertEqual(self.journal.actions,1)

    def test_missing_version_result_is_a_concrete_blocker_without_work(self):
        self.native_contexts['checks']=[]
        result=self.run_seed()
        self.assertEqual(result['state'],'requires_review');self.assertTrue(result['reason'])
        self.api.transfer.assert_not_called();self.assertEqual(self.journal.actions,0)

    def test_ambiguous_version_result_is_not_resolved_by_list_order(self):
        self.native_contexts['checks']*=2
        result=self.run_seed()
        self.assertEqual(result['state'],'requires_review')
        self.api.transfer.assert_not_called();self.assertEqual(self.journal.actions,0)

    def test_failed_version_result_never_seeds_consumers(self):
        self.native_checks[0]['state']='failed'
        result=self.run_seed()
        self.assertEqual(result['state'],'requires_review')
        self.api.transfer.assert_not_called()

    def test_rule_changes_are_rejected_instead_of_inferred(self):
        self.rule['recipe']='unreviewed-input';self.write_rule()
        with self.assertRaises(ValueError):self.run_seed()
        self.api.transfer.assert_not_called()

    def test_native_runtime_changes_invalidate_the_seed_stage(self):
        self.run_seed();self.runtime['portable']='runtime fixture 2';self.run_seed()
        self.assertEqual(self.api.transfer.call_count,2);self.assertEqual(self.journal.actions,2)

    def test_binary_runtime_bytes_change_the_seed_key(self):
        self.run_seed();self.runtime_file.write_bytes(b'changed runtime binary');self.run_seed()
        self.assertEqual(self.api.transfer.call_count,2);self.assertEqual(self.journal.actions,2)

    def test_selected_lineage_change_invalidates_an_unchanged_context(self):
        self.run_seed();self.lineage_extra.write_bytes(b'{"revision":2}');self.run_seed()
        self.assertEqual(self.api.transfer.call_count,2);self.assertEqual(self.journal.actions,2)

    def test_current_rule_code_change_invalidates_the_static_proof(self):
        self.run_seed();self.tool_file.write_bytes(b'reviewed next input rules');self.declarations();self.run_seed()
        self.assertEqual(self.api.transfer.call_count,2);self.assertEqual(self.journal.actions,2)

    def test_corrupt_proof_is_not_silently_rebuilt_on_a_warm_repeat(self):
        first=self.run_seed();Path(first['report']).write_bytes(b'corrupt immutable proof')
        self.assertEqual(self.run_seed()['state'],'requires_review')
        self.api.transfer.assert_called_once();self.assertEqual(self.journal.actions,1)

    def test_same_named_consumer_role_requires_the_same_source_address(self):
        consumers=copy.deepcopy(self.consumers)
        consumers['tutorial-update']['functions']['input_u32']='0x1400ff000'
        with self.assertRaisesRegex(ValueError,'primitive differs'):
            SEED.inventory(consumers,self.old)

    def test_old_packet_source_cannot_be_substituted_for_the_reviewed_baseline(self):
        consumers=copy.deepcopy(self.consumers);consumers['quest-sync']['source_sha256']='f'*64
        with self.assertRaisesRegex(ValueError,'source or root scope'):
            SEED.inventory(consumers,self.old)

    def test_vector_and_generic_reader_remain_pending_even_when_shared(self):
        result=SEED.inventory(self.consumers,self.old)
        for role in ('vector','reader'):
            at=self.consumers['quest-sync']['functions'][role]
            root=next(r for r in result['roots'] if r['address']==at)
            self.assertTrue(root['shared']);self.assertEqual(root['state'],'pending_consumer_transfer')

    def test_unrelated_full_target_difference_rejects_seven_matching_roles(self):
        def transfer(*args):
            value=copy.deepcopy(self.target);value['reader']='0x1400fff00'
            mapping={self.old['native_input']['functions'][role]:self.target['native_input']['functions'][role]
                for role in self.role_map.values()}
            return value,dict(mapping=mapping)
        self.api.transfer.side_effect=transfer
        result=self.run_seed()
        self.assertEqual(result['state'],'requires_review')
        self.assertIn('independent target',result['reason'])
        self.assertFalse(list((self.root/'knowledge'/SEED.CATEGORY).glob('*/manifest.json')))

    def test_changed_baseline_bytes_require_a_new_pointer(self):
        Path(self.baseline['path']).write_bytes(WORKFLOW.canonical(dict(source_sha256='f'*64)))
        result=self.run_seed()
        self.assertEqual(result['state'],'requires_review');self.api.transfer.assert_not_called()

    def test_selector_cannot_point_outside_repository_native_contexts(self):
        outside=self.root/'other.json';outside.write_bytes(WORKFLOW.canonical(self.old))
        self.rule['version_baseline']=self.pointer(outside);self.write_rule()
        with self.assertRaisesRegex(ValueError,'repository native knowledge'):self.run_seed()

    def test_full_target_source_mismatch_is_not_accepted_from_a_passed_check(self):
        bad=copy.deepcopy(self.target);bad['source_sha256']=self.old_sha
        self.target_pointer=self.snapshot('generated-native-contexts',bad);self.declarations()
        result=self.run_seed()
        self.assertEqual(result['state'],'requires_review');self.api.transfer.assert_not_called()

    def test_new_hashed_cache_proof_cannot_elevate_consumer_admission(self):
        first=self.run_seed();proof=json.loads(Path(first['report']).read_bytes());proof['native_consumer_verified']=True
        pointer=self.snapshot(SEED.CATEGORY,proof);key=next(iter(self.journal.values))
        self.journal.values[key].update(report=pointer['path'],sha256=pointer['sha256'],native_consumer_verified=True)
        self.assertEqual(self.run_seed()['state'],'requires_review')
        self.api.transfer.assert_called_once()

    def test_static_analysis_mutation_of_selected_lineage_blocks_publication(self):
        original=self.api.transfer.side_effect
        def transfer(*args):
            value=original(*args);self.lineage_extra.write_bytes(b'{"mutation":"during transfer"}');return value
        self.api.transfer.side_effect=transfer
        result=self.run_seed()
        self.assertEqual(result['state'],'requires_review');self.assertIn('material changed',result['reason'])

    def test_runtime_mutation_during_analysis_cannot_publish_a_stale_seed(self):
        original=self.api.transfer.side_effect
        def transfer(*args):
            value=original(*args);self.runtime['portable']='changed during transfer';return value
        self.api.transfer.side_effect=transfer
        result=self.run_seed()
        self.assertEqual(result['state'],'requires_review');self.assertIn('runtime',result['reason'].lower())

    def test_warm_final_validation_completes_without_promoting_the_consumer(self):
        self.run_seed();warm=self.run_seed()
        self.assertFalse(warm['final_validation_completed']);self.assertTrue(warm['final_validation_pending'])
        self.store.validate()
        final=SEED.finalize(self.index,self.args,warm)
        self.assertTrue(final['final_validation_completed']);self.assertFalse(final['final_validation_pending'])
        for key in ('native_consumer_verified','runtime_activated','profile_activated'):
            self.assertIs(final[key],False)
        self.assertFalse(warm['final_validation_completed']);self.api.transfer.assert_called_once()

    def test_late_selected_tool_or_proof_change_blocks_final_validation(self):
        for kind in ('tool','proof'):
            with self.subTest(kind=kind):
                self.setUp();result=self.run_seed()
                path=self.tool_file if kind=='tool' else Path(result['report'])
                path.write_bytes(path.read_bytes()+b'!')
                with self.assertRaises(ValueError):SEED.finalize(self.index,self.args,result)
                self.assertFalse(result['final_validation_completed']);self.api.transfer.assert_called_once()

    def test_replacing_source_store_cannot_reuse_the_previous_owner_guard(self):
        result=self.run_seed();self.args.source_store=copy.copy(self.store)
        with self.assertRaises(ValueError):SEED.finalize(self.index,self.args,result)
        self.assertFalse(result['final_validation_completed']);self.api.transfer.assert_called_once()


if __name__=='__main__':unittest.main()
