"""Base preparation scope and byte provenance; fixtures do not admit OS or SDK."""
import copy
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch,Mock

from test_vampir_update_contracts import load

TOOL=load('update-native-version-prepare')


class PrepareInputsTests(unittest.TestCase):
    def test_only_the_two_declared_roots_are_allowed(self):
        c=dict(prepare='0x1000',constructor='0x2000')
        self.assertEqual(TOOL.roots(c),{4096,8192})
        for key in ('native_nm','native_system','native_combiners','native_platform','function_budget'):
            with self.subTest(key=key),self.assertRaises(ValueError):TOOL.roots(dict(c,**{key:{}}))
        with self.assertRaises(ValueError):TOOL.roots(dict(c,constructor='0x1000'))

    def test_data_needs_complete_file_backing_or_one_pe_zero_fill_interval(self):
        image=SimpleNamespace(pe=SimpleNamespace(base=0x1000,sections=[dict(name='.data',rva=0x100,size=32,raw_size=16)]))
        with patch.object(TOOL,'image_bytes',return_value=b'\x01\x02'):
            self.assertEqual(TOOL.data_input(image,0x1000,2),dict(storage='file',bytes='0102'))
        with patch.object(TOOL,'image_bytes',side_effect=ValueError('not file backed')):
            self.assertEqual(TOOL.data_input(image,0x1110,8)['storage'],'pe-zero-fill')
            for at,size in ((0x110f,8),(0x111f,2),(0x1120,1)):
                with self.subTest(at=at),self.assertRaisesRegex(ValueError,'outside file'):TOOL.data_input(image,at,size)

    def test_fixture_roots_cannot_alias_each_other_or_executed_code(self):
        context=dict(prepare='0x1000',constructor='0x2000',fixtures=dict(provider='0x3000'),send='0x4000')
        image=SimpleNamespace(pe=SimpleNamespace(base=0),containing=lambda at:at,roots={0x3000:(0x3000,0x3010),0x4000:(0x4000,0x4010)})
        self.assertEqual(set(TOOL.fixture_boundaries(image,context)),{'provider','send'})
        for changed in (dict(context,send='0x3000'),dict(context,fixtures=dict(provider='0x1000'))):
            with self.assertRaisesRegex(ValueError,'aliases'):TOOL.fixture_boundaries(image,changed)

    def test_only_the_declared_empty_logger_leaf_may_lack_unwind(self):
        c=dict(prepare='0x1000',constructor='0x2000',fixtures=dict(log='0x3000'),send='0x4000')
        image=SimpleNamespace(pe=SimpleNamespace(base=0),containing=lambda at:at if at==0x4000 else None,roots={0x4000:(0x4000,0x4010)})
        with patch.object(TOOL,'image_bytes',return_value=b'\xc2\0\0'):
            self.assertIn('logger leaf',TOOL.fixture_boundaries(image,c)['log']['scope'])
            with self.assertRaisesRegex(ValueError,'unwind entry'):
                TOOL.fixture_boundaries(image,dict(c,fixtures=dict(provider='0x3000')))
        with patch.object(TOOL,'image_bytes',return_value=b'\xc3\x90\x90'),self.assertRaisesRegex(ValueError,'unwind entry'):
            TOOL.fixture_boundaries(image,c)

    def test_every_proof_excludes_mutable_pointer_and_export_fields(self):
        c=dict(schema=1,prepare='0x1000',exports={'run':'hash'},transfer_proof={'path':'proof'},release_id='next')
        self.assertEqual(TOOL.plain(c),dict(schema=1,prepare='0x1000'))
        self.assertIn('exports',c)


class PrepareReportsTests(unittest.TestCase):
    def fixture(self):
        c=dict(source_sha256='a'*64,family='version-prepare',transfer_proof=dict(path='proof',sha256='b'*64))
        r=dict(source_sha256='a'*64,scope=TOOL.SCOPE,method='bounded_native',network_used=False,profile_activated=False,
            runtime_activated=False,proof=c['transfer_proof'],context_sha256='c'*64,cases=[dict(guards=True)]*64,
            native_nm_used=False,native_system_used=False,native_combiners_used=False,native_platform_used=False)
        return c,r

    def test_exact_native_matrix_requires_explicit_synthetic_helper_boundaries(self):
        c,r=self.fixture();TOOL.report_valid(r,c,'c'*64)
        changes=[dict(source_sha256='d'*64),dict(scope='full-entry'),dict(cases=[]),dict(cases=[dict(guards=False)]*64),dict(network_used=True)]
        changes.extend({key:True} for key in ('native_nm_used','native_system_used','native_combiners_used','native_platform_used'))
        for change in changes:
            with self.subTest(changes=tuple(change)),self.assertRaises(ValueError):TOOL.report_valid({**r,**change},c,'c'*64)

    def test_same_target_uses_published_proof_without_discovery(self):
        c,_=self.fixture();args=SimpleNamespace(root='root',knowledge='defs')
        with patch.object(TOOL,'load',return_value=SimpleNamespace(read=lambda _:{})),patch.object(TOOL,'published_contexts',return_value=[(Path('ctx'),c,3)]),\
                patch.object(TOOL,'validate') as verify,patch.object(TOOL,'checked',return_value={'same':'proof'}),\
                patch.object(TOOL,'planned',return_value='reused') as planned,patch.object(TOOL,'transfer',side_effect=AssertionError('No self-transfer')):
            self.assertEqual(TOOL.discover(None,args,'a'*64),'reused');verify.assert_called_once();planned.assert_called_once_with(c,{'same':'proof'})

    def test_published_entry_needs_source_bound_report_and_unique_source(self):
        c,r=self.fixture();row=dict(context=dict(path='ctx',sha256='c'*64),check=dict(path='report',sha256='d'*64),order=1)
        registry=dict(releases=[dict(source_sha256='a'*64,order=2)])
        with patch.object(TOOL,'checked',side_effect=lambda root,item,category:c if category=='generated-native-contexts' else r):
            self.assertEqual(TOOL.published_contexts('root',registry,value=dict(schema=1,contexts=[row]))[0][2],2)
            for value in (dict(schema=1,contexts=[row,row]),dict(schema=2,contexts=[row])):
                with self.assertRaises(ValueError):TOOL.published_contexts('root',registry,value=value)

    def test_publication_failure_does_not_replace_previous_index(self):
        c,r=self.fixture();declaration=dict(context=dict(path='ctx',sha256='c'*64));outcome=dict(state='passed',report='report',sha256='d'*64)
        workflow=SimpleNamespace(atomic=Mock())
        with tempfile.TemporaryDirectory() as directory:
            args=SimpleNamespace(root=Path(directory),knowledge=Path(directory))
            with patch.object(TOOL,'validate'),patch.object(TOOL,'checked',side_effect=lambda root,item,category:c if category=='generated-native-contexts' else {**r,'native_nm_used':True}):
                with self.assertRaises(ValueError):TOOL.publish(None,args,'a'*64,declaration,outcome)
            workflow.atomic.assert_not_called()

    def test_changed_schema_or_cycle_stops_before_reading_source(self):
        c,_=self.fixture();args=SimpleNamespace(root=Path('root'))
        with patch.object(TOOL,'checked',return_value={}),patch.object(TOOL,'tools',return_value={}):
            with self.assertRaisesRegex(ValueError,'cycle'):TOOL.validate(None,args,c,{'b'*64})
            with self.assertRaisesRegex(ValueError,'proof fields'):TOOL.validate(None,args,c)


if __name__=='__main__':unittest.main()
