"""Synthetic strict archive transfer boundaries; no native, Ghidra or game IO."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).parent/'resource-tools/vampir'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


TOOL=load('update-native-archive-wire')
BASE=0x140000000


def context_fixture():
    bindings=dict(length='0x1100',convert='0x1200',encoder='0x1300',**{'string-writer':'0x1400'})
    archive={name:hex(0x2000+i*0x100) for i,name in enumerate(('base-constructor','bool','constructor','growth','raw','string','table','u16','u32','u64','u8'))}
    return dict(schema=1,family='archive-wire',source_sha256='a'*64,source='target.exe',bindings=bindings,
        archive=archive,packets={'game-login':dict(writer='0x5000',table='0x6000',object_size=32,fields=[['string',16]]),
            'game-version':dict(writer='0x7000',table='0x8000',object_size=32,fields=[['u32',16]])},
        transfer_proof=dict(path='proof',sha256='b'*64),layout=TOOL.LAYOUT)


class ArchiveClosureTests(unittest.TestCase):
    def rows(self):
        return [dict(address=0x1000,call=False,branch=False,direct_target=None,rip_references=[0x9000],operands='lea'),
            dict(address=0x1004,call=True,branch=False,direct_target=0x2000,rip_references=[],operands='call'),
            dict(address=0x1008,call=False,branch=True,direct_target=0x1000,rip_references=[],operands='jne')]

    def pair(self,before,after,mapping):
        common=SimpleNamespace(signature=lambda native,rows:['same-shape'])
        with patch.object(TOOL,'load',return_value=common):TOOL.pair_rows(None,before,after,mapping)

    def test_each_instruction_callee_and_data_edge_is_relocated_consistently(self):
        old=self.rows();new=copy.deepcopy(old)
        for row in new:row['address']+=0x20
        new[0]['rip_references']=[0x9020];new[1]['direct_target']=0x2020;new[2]['direct_target']=0x1020
        mapping={};self.pair(old,new,mapping)
        self.assertEqual(mapping,{0x1000:0x1020,0x1004:0x1024,0x1008:0x1028,0x9000:0x9020,0x2000:0x2020})

    def test_external_branch_is_rejected_even_if_masked_signature_matches(self):
        rows=self.rows();rows[-1]['direct_target']=0x3000
        with self.assertRaisesRegex(ValueError,'external branch'):self.pair(rows,copy.deepcopy(rows),{})

    def test_repeated_callee_or_rip_mapping_cannot_disagree(self):
        old=self.rows();new=copy.deepcopy(old);new[1]['direct_target']=0x2010
        with self.assertRaisesRegex(ValueError,'inconsistent'):self.pair(old,new,{0x2000:0x2020})
        new=copy.deepcopy(old);new[0]['rip_references']=[0x9010]
        with self.assertRaisesRegex(ValueError,'inconsistent'):self.pair(old,new,{0x9000:0x9020})

    def test_indirect_dispatch_and_data_edge_count_are_not_ignored(self):
        old=self.rows();old[1].update(direct_target=None,operands='qword ptr [rax + 0x88]')
        new=copy.deepcopy(old);new[1]['operands']='qword ptr [rax + 0x90]'
        with self.assertRaisesRegex(ValueError,'indirect dispatch'):self.pair(old,new,{})
        new=copy.deepcopy(old);new[0]['rip_references']=[]
        with self.assertRaisesRegex(ValueError,'data edge count'):self.pair(old,new,{})

    def test_changed_whole_shape_is_rejected_before_mapping(self):
        common=SimpleNamespace(signature=lambda native,rows:rows[0]['address'])
        old=self.rows();new=copy.deepcopy(old);new[0]['address']+=1;mapping={}
        with patch.object(TOOL,'load',return_value=common),self.assertRaisesRegex(ValueError,'whole instruction shape'):
            TOOL.pair_rows(None,old,new,mapping)
        self.assertEqual(mapping,{})

    def test_relocated_rip_import_displacement_is_accepted_but_slot_mapping_is_consistent(self):
        old=self.rows();old[1].update(direct_target=None,rip_references=[0x8000],operands='qword ptr [rip + 0x10]')
        new=copy.deepcopy(old);new[1].update(rip_references=[0x8020],operands='qword ptr [rip + 0x20]')
        mapping={};self.pair(old,new,mapping);self.assertEqual(mapping[0x8000],0x8020)
        with self.assertRaisesRegex(ValueError,'inconsistent'):self.pair(old,new,{0x8000:0x8030})

    def test_unrelated_invalid_root_candidate_is_skipped_but_baseline_error_is_fatal(self):
        before=SimpleNamespace(containing=lambda at:'old',roots={'old':(0x1000,0x1010)},pe=SimpleNamespace(base=0))
        after=SimpleNamespace(roots={'bad':(0x1020,0x1030),'good':(0x1040,0x1050)},pe=SimpleNamespace(base=0))
        def rows(native,image,at):
            if image is after and at==0x1020:raise ValueError('Unrelated chained fragment cannot be a candidate')
            return ['matching-complete-shape']
        common=SimpleNamespace(signature=lambda native,rows:rows)
        with patch.object(TOOL,'load',return_value=common):
            self.assertEqual(TOOL.unique_root(None,SimpleNamespace(rows=rows),before,after,0x1000),0x1040)
            with self.assertRaisesRegex(ValueError,'Broken reviewed baseline'):
                TOOL.unique_root(None,SimpleNamespace(rows=Mock(side_effect=ValueError('Broken reviewed baseline'))),before,after,0x1000)


class ArchiveTableTests(unittest.TestCase):
    def setUp(self):
        self.old_values=[BASE+0x10000+i*0x100 for i in range(31)]
        self.new_values=[value+0x30 for value in self.old_values]
        self.before=object();self.after=object();self.baseline=dict(archive={'table':hex(BASE+0x2000)})
        self.current=dict(archive={'table':hex(BASE+0x2030)});self.mapping={}
        for name,slot in TOOL.SLOTS.items():
            old=self.old_values[slot//8];new=self.new_values[slot//8]
            self.baseline['archive'][name]=hex(old);self.current['archive'][name]=hex(new);self.mapping[old]=new
        self.old=struct.pack('<31Q',*self.old_values);self.new=struct.pack('<31Q',*self.new_values)
        self.baseline['archive_table_sha256']=hashlib.sha256(self.old).hexdigest()

    def relation(self):
        common=SimpleNamespace(image_bytes=lambda image,at,size:self.old if image is self.before else self.new)
        with patch.object(TOOL,'load',return_value=common):
            return TOOL.table_relation(self.before,self.after,self.baseline,self.current,self.mapping)

    def test_used_slots_have_exact_roles_and_unused_slots_are_explicitly_excluded(self):
        relation=self.relation()
        self.assertEqual({row['slot'] for row in relation['used_slots']},set(TOOL.SLOTS.values()))
        self.assertEqual(set(relation['excluded_slots'])|set(TOOL.SLOTS.values()),set(range(0,248,8)))
        self.assertEqual(relation['sha256'],hashlib.sha256(self.new).hexdigest())
        self.assertIn('unexecuted',relation['excluded_scope'])

    def test_used_pointer_change_cannot_be_hidden_by_new_whole_table_hash(self):
        self.new_values[0x28//8]+=8;self.new=struct.pack('<31Q',*self.new_values)
        with self.assertRaisesRegex(ValueError,'used table slot'):self.relation()

    def test_alias_topology_changes_even_in_unexecuted_entries_are_rejected(self):
        self.new_values[0]=self.new_values[1];self.new=struct.pack('<31Q',*self.new_values)
        with self.assertRaisesRegex(ValueError,'alias layout'):self.relation()

    def test_baseline_table_corruption_is_not_a_new_valid_baseline(self):
        self.baseline['archive_table_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'baseline table changed'):self.relation()


class ArchiveScopeTests(unittest.TestCase):
    def growth_fixture(self):
        context=context_fixture();context.update(archive_leaves={'0x9000':{}},helpers=dict(memcpy='0x9100'),
            fixtures=dict(archive_slot=40,utf8_allocate='0x9200'))
        growth=int(context['archive']['growth'],16)
        image=SimpleNamespace(containing=lambda at:'root',roots={'root':(growth,growth+0x20)},pe=SimpleNamespace(base=0))
        return context,image

    def test_growth_fixture_requires_a_real_unwind_entry(self):
        context,image=self.growth_fixture();result=TOOL.growth_boundary(image,context)
        self.assertEqual(result['boundary'],'unwind-root');self.assertIn('not executed',result['scope'])
        image.containing=lambda at:None
        with self.assertRaisesRegex(ValueError,'explicit unwind root'):TOOL.growth_boundary(image,context)
        image.containing=lambda at:'root';image.roots['root']=(0x100,0x200)
        with self.assertRaisesRegex(ValueError,'explicit unwind root'):TOOL.growth_boundary(image,context)

    def test_growth_fixture_cannot_alias_executed_root_leaf_copy_or_allocator(self):
        for address in ('0x1100','0x1300','0x9000','0x9100','0x9200'):
            context,image=self.growth_fixture();context['archive']['growth']=address
            image.roots['root']=(int(address,16),int(address,16)+0x20)
            with self.subTest(address=address),self.assertRaisesRegex(ValueError,'overlaps'):
                TOOL.growth_boundary(image,context)

    def test_root_scope_contains_fourteen_explicit_functions_but_never_growth_or_table(self):
        context=context_fixture();roots=TOOL.roots(context)
        self.assertEqual(len(roots),14)
        self.assertNotIn(int(context['archive']['growth'],16),roots)
        self.assertNotIn(int(context['archive']['table'],16),roots)
        context['packets']['game-login']['writer']=context['bindings']['length']
        with self.assertRaisesRegex(ValueError,'root scope'):TOOL.roots(context)

    def test_packet_scope_field_offsets_width_and_overlap_are_bounded(self):
        packets=context_fixture()['packets'];TOOL.validate_packets(packets)
        for mutate in (lambda p:p['game-login'].update(object_size=1024),
                lambda p:p['game-login'].update(fields=[['string',24]]),
                lambda p:p['game-login'].update(fields=[['u32',16],['u8',17]]),
                lambda p:p.update(other=p['game-login']),
                lambda p:p['game-login'].update(fields=[['unknown',16]])):
            value=copy.deepcopy(packets);mutate(value)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):TOOL.validate_packets(value)

    def semantic(self,context):
        return dict(source_sha256=context['source_sha256'],scope=TOOL.SCOPE,method='bounded_native',network_used=False,
            profile_activated=False,runtime_activated=False,proof=context['transfer_proof'],context_sha256='c'*64,
            archive=context['archive'],cases=[{}]*45,wire_cases=[dict(guards=True)]*64)

    def test_semantic_counts_scope_guards_source_and_context_are_required(self):
        context=context_fixture();valid=self.semantic(context);TOOL.report_valid(valid,context,'c'*64)
        for updates in (dict(scope='function_only'),dict(cases=[{}]*44),dict(wire_cases=[dict(guards=True)]*63),
                dict(wire_cases=[dict(guards=False)]*64),dict(source_sha256='0'*64),dict(context_sha256='0'*64),
                dict(runtime_activated=True),dict(network_used=True),dict(proof={})):
            with self.subTest(updates=updates),self.assertRaisesRegex(ValueError,'semantic proof'):
                TOOL.report_valid({**valid,**updates},context,'c'*64)

    def test_same_target_discovery_reuses_existing_context_without_new_proof(self):
        context=context_fixture();context['exports']={'run-known':'d'*64};proof=dict(baseline=dict(path='baseline',sha256='e'*64),
            writer=dict(path='writer',sha256='f'*64));module=SimpleNamespace(read=lambda _:dict(releases=[]))
        with patch.object(TOOL,'load',return_value=module),patch.object(TOOL,'published_contexts',return_value=[(Path('context'),context,1)]),\
                patch.object(TOOL,'validate') as validate,patch.object(TOOL,'checked',return_value=proof),patch.object(TOOL,'tools',return_value={}):
            plan=TOOL.discover(None,SimpleNamespace(root=Path('.'),knowledge=Path('.')),context['source_sha256'])
        validate.assert_called_once();self.assertNotIn('exports',plan['context']);self.assertEqual(len(plan['exports']),14)
        self.assertEqual(plan['context']['transfer_proof'],context['transfer_proof'])

    def test_publication_validates_report_before_atomic_write(self):
        context=context_fixture();report=self.semantic(context);report['scope']='function_only'
        declaration=dict(context=dict(path='context',sha256='c'*64));outcome=dict(state='passed',report='report',sha256='d'*64)
        workflow=SimpleNamespace(atomic=Mock());args=SimpleNamespace(root=Path('.'),knowledge=Path('.'))
        def checked(root,item,category):return context if category=='generated-native-contexts' else report
        with patch.object(TOOL,'checked',side_effect=checked),patch.object(TOOL,'validate'),\
                patch.object(TOOL,'load',return_value=workflow),self.assertRaisesRegex(ValueError,'semantic proof'):
            TOOL.publish(None,args,context['source_sha256'],declaration,outcome)
        workflow.atomic.assert_not_called()

    def test_unreviewed_source_or_duplicate_index_entry_is_rejected(self):
        context=context_fixture();report=self.semantic(context)
        row=dict(context=dict(path='context',sha256='c'*64),check=dict(path='check',sha256='d'*64),order=1)
        def checked(root,item,category):return context if category=='generated-native-contexts' else report
        with patch.object(TOOL,'checked',side_effect=checked):
            self.assertEqual(len(TOOL.published_contexts(Path('.'),dict(releases=[]),value=dict(schema=1,contexts=[row]))),1)
            for value in (dict(schema=1,contexts=[row,row]),dict(schema=2,contexts=[row])):
                with self.assertRaises(ValueError):TOOL.published_contexts(Path('.'),dict(releases=[]),value=value)


class ArchiveProofTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.root=Path(temporary.name).resolve()
        self.path=self.root/'knowledge/generated-native-contexts/baseline.json';self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps(dict(source_sha256='d'*64)))
        self.context=context_fixture();self.context['exports']={'run-known':'e'*64}
        self.plain={k:v for k,v in self.context.items() if k not in ('exports','transfer_proof')}
        self.relocation=dict(mapping={'0x1000':'0x1010'},table=dict(used_slots=[]))
        self.proof=dict(schema=1,adapter=TOOL.ADAPTER,scope=TOOL.SCOPE,tools={},runtime_activated=False,
            target=copy.deepcopy(self.plain),relocation=copy.deepcopy(self.relocation),
            baseline=dict(path=str(self.path),sha256=hashlib.sha256(self.path.read_bytes()).hexdigest()),
            writer=dict(path='writer',sha256='f'*64))
        self.writer=dict(source_sha256=self.context['source_sha256']);self.writer_validate=Mock()
        modules={'update-native-string-writer':SimpleNamespace(validate=self.writer_validate),
            'build-native-entry-code':object(),'update-bindings':object()}
        self.args=SimpleNamespace(root=self.root,source_store=SimpleNamespace(image=lambda *args:object()))
        for mocked in (patch.object(TOOL,'tools',return_value={}),
                patch.object(TOOL,'checked',side_effect=lambda root,item,category:self.proof if category==TOOL.PROOFS else self.writer),
                patch.object(TOOL,'load',side_effect=lambda name:modules[name]),
                patch.object(TOOL,'digest',side_effect=lambda path:hashlib.sha256(Path(path).read_bytes()).hexdigest()),
                patch.object(TOOL,'export_coverage'),
                patch.object(TOOL,'transfer',side_effect=lambda *args:(self.plain,self.relocation))):
            mocked.start();self.addCleanup(mocked.stop)

    def test_valid_proof_rechecks_writer_and_both_export_scopes(self):
        self.assertIs(TOOL.validate(None,self.args,self.context),self.context)
        self.writer_validate.assert_called_once()
        self.assertEqual(TOOL.export_coverage.call_count,2)

    def test_schema_tools_layout_or_payload_forgery_is_rejected(self):
        for updates in (dict(schema=2),dict(tools={'changed':'0'*64}),dict(scope='function_only'),dict(runtime_activated=True)):
            original=copy.deepcopy(self.proof);self.proof.update(updates)
            with self.subTest(updates=updates),self.assertRaisesRegex(ValueError,'proof fields'):
                TOOL.validate(None,self.args,self.context)
            self.proof=original
        changed=copy.deepcopy(self.context);changed['layout']={}
        with self.assertRaisesRegex(ValueError,'layout'):TOOL.validate(None,self.args,changed)

    def test_relocated_closure_or_target_writer_source_cannot_be_forged(self):
        self.proof['relocation']={'mapping':{}}
        with self.assertRaisesRegex(ValueError,'relocated closure'):TOOL.validate(None,self.args,self.context)
        self.proof['relocation']=self.relocation;self.writer['source_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'writer source'):TOOL.validate(None,self.args,self.context)

    def test_proof_cycle_and_baseline_path_scope_are_rejected(self):
        with self.assertRaisesRegex(ValueError,'cycle/depth'):
            TOOL.validate(None,self.args,self.context,seen={self.context['transfer_proof']['sha256']})
        self.proof['baseline']['path']=str(self.root/'outside.json')
        with self.assertRaisesRegex(ValueError,'outside reviewed'):TOOL.validate(None,self.args,self.context)


if __name__=='__main__':unittest.main()
