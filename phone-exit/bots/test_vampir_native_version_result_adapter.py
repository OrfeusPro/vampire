"""Synthetic Version input proof/driver checks; no native or research writers."""
import copy
import hashlib
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch,Mock

from test_vampir_update_contracts import load

TOOL=load('update-native-version-result')


def row(at,**kw):
    return dict(address=at,bytes='90',mnemonic='nop',operands='',call=False,branch=False,
        direct_target=None,rip_references=[],**kw) if not kw else {**row(at),**kw}


class VersionEdgesTests(unittest.TestCase):
    def pair(self,before,after,mapping=None,tail=False):
        common=SimpleNamespace(signature=lambda _,rows:[(r['bytes'],bool(r['call']),bool(r['branch'])) for r in rows])
        with patch.object(TOOL,'load',return_value=common):
            mapping={} if mapping is None else mapping
            TOOL.pair_rows(None,before,after,mapping,tail=tail);return mapping

    def test_call_and_data_relocations_are_consistent(self):
        before=[row(100,call=True,direct_target=500),row(101,rip_references=[800])]
        after=[row(200,call=True,direct_target=600),row(201,rip_references=[900])]
        self.assertEqual(self.pair(before,after),{100:200,101:201,500:600,800:900})
        with self.assertRaisesRegex(ValueError,'Inconsistent'):self.pair(before,after,{500:601})

    def test_external_branch_and_indirect_slot_change_are_rejected(self):
        with self.assertRaisesRegex(ValueError,'external branch'):
            self.pair([row(100,branch=True,direct_target=600)],[row(200,branch=True,direct_target=700)])
        with self.assertRaisesRegex(ValueError,'indirect dispatch'):
            self.pair([row(100,call=True,operands='qword ptr [rax + 0x58]')],[row(200,call=True,operands='qword ptr [rax + 0x60]')])

    def test_only_exact_typed_u8_tail_is_accepted(self):
        old=row(100,branch=True,operands='qword ptr [rax + 0x90]');new=dict(old,address=200)
        self.pair([old],[new],tail=True)
        for operand in ('qword ptr [rax + 0x88]','rax'):
            with self.subTest(operand=operand),self.assertRaises(ValueError):
                self.pair([dict(old,operands=operand)],[dict(new,operands=operand)],tail=True)

    def test_root_ambiguity_resolves_only_through_a_checked_caller(self):
        old={10:[row(10,call=True,direct_target=20)],20:[row(20)]}
        new={110:[row(110,call=True,direct_target=220)],120:[row(120)],220:[row(220)]}
        bindings=SimpleNamespace(rows=lambda native,image,at:(old if image=='old' else new)[at])
        def candidates(*args):return [110] if args[-1]==10 else [120,220]
        common=SimpleNamespace(signature=lambda _,rows:[(r['bytes'],bool(r['call'])) for r in rows])
        with patch.object(TOOL,'candidates',side_effect=candidates),patch.object(TOOL,'load',return_value=common):
            self.assertEqual(TOOL.resolve_roots(None,bindings,'old','new',{10,20},{}),{'0xa':'0x6e','0x14':'0xdc'})
            with self.assertRaisesRegex(ValueError,'ambiguous'):
                TOOL.resolve_roots(None,bindings,'old','new',{20},{})

    def test_bad_target_candidate_is_skipped_but_bad_baseline_is_fatal(self):
        before=SimpleNamespace(containing=lambda _:0,roots={0:(10,11)})
        after=SimpleNamespace(pe=SimpleNamespace(base=0),roots={1:(110,111),2:(210,211)})
        def rows(native,image,at):
            if image is after and at==110:raise ValueError('bad candidate')
            return [row(at)]
        common=SimpleNamespace(signature=lambda _,rows:[r['bytes'] for r in rows])
        with patch.object(TOOL,'load',return_value=common):
            self.assertEqual(TOOL.candidates(None,SimpleNamespace(rows=rows),before,after,10),[210])
            with self.assertRaisesRegex(ValueError,'bad baseline'):
                TOOL.candidates(None,SimpleNamespace(rows=lambda *args:(_ for _ in ()).throw(ValueError('bad baseline'))),before,after,10)

    def test_alias_table_and_known_roles_cannot_change(self):
        old=struct.pack('<3Q',10,10,20);new=struct.pack('<3Q',110,110,120)
        with patch.object(TOOL,'image_bytes',side_effect=lambda image,at,size:old if image=='old' else new):
            mapping={10:110}
            result=TOOL.table_links('old','new',100,200,old.hex(),mapping,{0})
            self.assertEqual(result['excluded_slots'],[8,16]);self.assertEqual(mapping[20],120)
            with self.assertRaisesRegex(ValueError,'Inconsistent'):
                TOOL.table_links('old','new',100,200,old.hex(),{10:130},{0})
        bad=struct.pack('<3Q',110,111,120)
        with patch.object(TOOL,'image_bytes',side_effect=lambda image,at,size:old if image=='old' else bad),self.assertRaises(ValueError):
            TOOL.table_links('old','new',100,200,old.hex(),{},set())

    def test_fifteen_roots_and_declared_input_names_are_mandatory(self):
        functions={name:hex(100+i) for i,name in enumerate(sorted(TOOL.INPUT_NAMES))}
        context=dict(reader=hex(500),native_input=dict(functions=functions))
        self.assertEqual(len(TOOL.roots(context)),15)
        changed=copy.deepcopy(context);changed['native_input']['functions'].pop('raw')
        with self.assertRaises(ValueError):TOOL.roots(changed)
        context['reader']=functions['raw']
        with self.assertRaises(ValueError):TOOL.roots(context)


class VersionProofTests(unittest.TestCase):
    def context_and_report(self):
        pointer=dict(path='proof',sha256='b'*64)
        context=dict(source_sha256='a'*64,family='version-result',transfer_proof=pointer,native_input=dict(portable_buffer_proof=pointer))
        report=dict(source_sha256='a'*64,scope=TOOL.SCOPE,method='bounded_native',network_used=False,profile_activated=False,
            runtime_activated=False,proof=pointer,context_sha256='c'*64,cases=[dict(returned=1,consumed=17)]*32,
            truncated=[dict(returned=0)]*17,failures=[dict(returned=0)]*5,construction_cases=[dict(guards=True)]*72,
            extra=dict(returned=1,consumed=17))
        return context,report

    def test_plain_proof_has_no_self_reference_or_export_list(self):
        context,_=self.context_and_report();context.update(exports={'run-a':'a'*64},release_id='test')
        context['native_input'].update(exports={'run-b':'b'*64})
        result=TOOL.plain(context)
        self.assertNotIn('transfer_proof',result);self.assertNotIn('exports',result)
        self.assertNotIn('portable_buffer_proof',result['native_input']);self.assertNotIn('exports',result['native_input'])
        self.assertIn('portable_buffer_proof',context['native_input'])

    def test_exact_native_case_matrix_and_scope_required(self):
        context,report=self.context_and_report();TOOL.report_valid(report,context,'c'*64)
        mutations=[dict(scope='whole-game'),dict(source_sha256='d'*64),dict(cases=[]),dict(truncated=[]),dict(failures=[]),
            dict(construction_cases=[dict(guards=False)]*72),dict(extra=dict(returned=1,consumed=18)),dict(runtime_activated=True)]
        for changes in mutations:
            with self.subTest(changes=tuple(changes)),self.assertRaises(ValueError):TOOL.report_valid({**report,**changes},context,'c'*64)

    def test_same_source_reuses_existing_context_without_building_another_proof(self):
        context,_=self.context_and_report();args=SimpleNamespace(root='root',knowledge='defs')
        with patch.object(TOOL,'load',return_value=SimpleNamespace(read=lambda _:{})),\
                patch.object(TOOL,'published_contexts',return_value=[(Path('context'),context,3)]),\
                patch.object(TOOL,'validate') as validate,patch.object(TOOL,'checked',return_value={'proof':'same'}) as checked,\
                patch.object(TOOL,'planned',return_value='reused') as planned,patch.object(TOOL,'transfer',side_effect=AssertionError('No new proof chain')):
            self.assertEqual(TOOL.discover(None,args,'a'*64),'reused');validate.assert_called_once();planned.assert_called_once_with(context,{'proof':'same'})

    def test_portable_admission_rejects_wrong_sha_nested_fields_and_endian_before_validation(self):
        raw=b'actual';sha=hashlib.sha256(raw).hexdigest()
        target=dict(source_sha256=sha,native_input=dict(source_sha256=sha,buffer_construction=dict(base_table='0x1000',reading_mode=1,reading_endian=0)),layout=TOOL.LAYOUT)
        pointer=dict(path='proof',sha256='b'*64);nested=TOOL.attach_proof(target,pointer)['native_input']
        h=SimpleNamespace(root=Path('library'),sha=sha,raw=raw)
        with patch.object(TOOL,'checked',return_value=dict(target=target)),patch.object(TOOL,'validate',side_effect=AssertionError('No downstream validation on corrupt inputs')):
            for field in ('sha','nested'):
                changed=copy.deepcopy(nested)
                if field=='nested':changed['buffer_construction']['reading_endian']=1
                else:changed['source_sha256']='a'*64
                with self.subTest(field=field),self.assertRaisesRegex(ValueError,'context/source'):
                    TOOL.admit_input_buffer(h,changed)

    def test_valid_portable_hook_validates_proof_and_actual_source_without_replay(self):
        raw=b'checked source';sha=hashlib.sha256(raw).hexdigest();pointer=dict(path='proof',sha256='b'*64)
        target=dict(source_sha256=sha,native_input=dict(source_sha256=sha,buffer_construction=dict(base_table='0x1000',reading_mode=1,reading_endian=0)),layout=TOOL.LAYOUT)
        context=TOOL.attach_proof(target,pointer)['native_input'];store=SimpleNamespace(_sources={},_images={},validate=Mock())
        index=object();h=SimpleNamespace(root=Path('library'),sha=sha,raw=raw,image=object())
        modules={'knowledge-index':SimpleNamespace(api=lambda:index),'update-bindings':SimpleNamespace(SourceStore=lambda *args:store)}
        with patch.object(TOOL,'checked',return_value=dict(target=target)),patch.object(TOOL,'load',side_effect=lambda name:modules[name]),patch.object(TOOL,'validate') as validate:
            self.assertTrue(TOOL.admit_input_buffer(h,context));validate.assert_called_once();store.validate.assert_called_once()
        self.assertEqual(store._sources[sha],raw);self.assertIs(store._images[sha],h.image)

    def test_publication_validates_semantic_report_before_atomic_pointer_write(self):
        context,report=self.context_and_report();declaration=dict(context=dict(path='context',sha256='c'*64));outcome=dict(state='passed',report='check',sha256='d'*64)
        workflow=SimpleNamespace(atomic=Mock(),canonical=lambda v:b'{}')
        registry=SimpleNamespace(read=lambda _:dict(releases=[dict(source_sha256='a'*64,order=1)]))
        with tempfile.TemporaryDirectory() as directory:
            args=SimpleNamespace(root=Path(directory),knowledge=Path(directory))
            with patch.object(TOOL,'validate'),patch.object(TOOL,'checked',side_effect=lambda root,item,category:context if category=='generated-native-contexts' else {**report,'cases':[]}),\
                    patch.object(TOOL,'load',side_effect=lambda name:registry if name=='native-release-registry' else workflow):
                with self.assertRaises(ValueError):TOOL.publish(None,args,'a'*64,declaration,outcome)
            workflow.atomic.assert_not_called()

    def test_proof_cycle_and_scope_cannot_be_forged(self):
        context,_=self.context_and_report();args=SimpleNamespace(root=Path('root'))
        with patch.object(TOOL,'checked',return_value={}):
            with self.assertRaisesRegex(ValueError,'cycle'):TOOL.validate(None,args,context,{'b'*64})
            with self.assertRaisesRegex(ValueError,'fields, tools'):
                TOOL.validate(None,args,context)


if __name__=='__main__':unittest.main()
