"""Synthetic base Login preparation proof tests; no native/game/research IO."""
import copy
import itertools
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from test_vampir_update_contracts import load

TOOL=load('update-native-login-prepare')


class LoginInputsTests(unittest.TestCase):
    def setUp(self):
        self.old,self.new=object(),object();self.prepare=0x1000;self.mapping={}
        self.baseline=dict(prepare=hex(self.prepare),globals=dict(text='0x3000',tag_pointer='0x3100',enabled='0x3200',number='0x3300',enum='0x3400'),
            tag_literal='0x5000',compiled_tag_source=dict(literal='0x5000',value='A'*32),send_argument_global='0x3500',format_literal='0x3600',event_literal='0x3700')
        addresses={'text_count':0x3008,'text_pointer':0x3000,'compiled_tag_pointer':0x3100,'enabled':0x3200,'number':0x3300,
            'send_argument':0x3500,'format_literal':0x3600,'event_literal':0x3700}
        self.rows=[];self.memory={};self.roles={}
        for number,(offset,(role,size)) in enumerate(TOOL.DATA_ROLES.items()):
            at=addresses.get(role,0x4000+number*0x20);self.mapping[at]=at+0x10000;self.roles[role]=at
            self.rows.append(dict(address=self.prepare+offset,rip_references=[at]))
            if role in TOOL.PLATFORMS:raw=(TOOL.PLATFORMS[role]+'\0').encode('utf-16le')
            elif role=='compiled_tag_pointer':raw=struct.pack('<Q',0x5000)
            elif role=='format_literal':raw=('RdPeer::Login() - ServerId( %d )'+'\0').encode('utf-16le')
            elif role=='event_literal':raw=('{0}'+'\0').encode('utf-16le')
            else:raw=bytes(size)
            value=dict(storage='file',bytes=raw.hex())
            self.memory[(self.old,at,size)]=value
            self.memory[(self.new,at+0x10000,size)]=dict(storage='file',bytes=(struct.pack('<Q',0x6000) if role=='compiled_tag_pointer' else raw).hex())
        self.mapping[0x3400]=0x13400
        for image,at in ((self.old,0x3400),(self.new,0x13400)):self.memory[(image,at,4)]=dict(storage='file',bytes='01000000')
        bindings=SimpleNamespace(rows=lambda *args:self.rows)
        self.modules={'build-native-entry-code':object(),'update-bindings':bindings}
        self.tag=b'A'*32+b'\0'
        for mocked in (patch.object(TOOL,'load',side_effect=lambda name:self.modules[name]),
                patch.object(TOOL,'data_input',side_effect=lambda image,at,size:copy.deepcopy(self.memory[(image,at,size)])),
                patch.object(TOOL,'image_bytes',side_effect=lambda image,at,size:b'A'*32+b'\0' if image is self.old else self.tag)):
            mocked.start();self.addCleanup(mocked.stop)

    def typed(self):return TOOL.typed_data(self.old,self.new,self.baseline,self.mapping)

    def test_all_reviewed_rip_roles_and_constructor_enum_are_pinned(self):
        result=self.typed();self.assertEqual(len(result),19)
        self.assertEqual([r['role'] for r in result].count('enabled'),3)
        tag=next(r for r in result if r['role']=='compiled_tag_pointer')
        self.assertEqual(tag['input']['literal'],'0x6000');self.assertEqual(tag['input']['value'],'A'*32)

    def test_unknown_rip_offset_and_shifted_global_role_are_rejected(self):
        self.rows.append(dict(address=self.prepare+9999,rip_references=[0x4000]))
        with self.assertRaisesRegex(ValueError,'static data roles'):self.typed()
        self.rows.pop();self.baseline['globals']['enabled']='0x3201'
        with self.assertRaisesRegex(ValueError,'global input linkage'):self.typed()

    def test_compiled_tag_requires_exact_32_uppercase_hex_and_terminator(self):
        self.tag=b'g'*32+b'\0'
        with self.assertRaisesRegex(ValueError,'hex literal'):self.typed()

    def test_platform_format_event_send_and_enum_values_are_not_arbitrary(self):
        for role,size in (('android',16),('format_literal',66),('event_literal',8),('send_argument',8)):
            at=self.roles[role];key=(self.new,self.mapping[at],size);old=self.memory[key]
            self.memory[key]=dict(storage='file',bytes='ff'*size)
            with self.subTest(role=role),self.assertRaises(ValueError):self.typed()
            self.memory[key]=old
        self.memory[(self.new,0x13400,4)]=dict(storage='file',bytes='02000000')
        with self.assertRaisesRegex(ValueError,'enum default'):self.typed()


class LoginProofTests(unittest.TestCase):
    def fixture(self):
        c=dict(source_sha256='a'*64,family='login-prepare',transfer_proof=dict(path='proof',sha256='b'*64))
        fields=('scenario','selector','empty','send_return','poison')
        cases=[dict(zip(fields,row),guards=True) for row in itertools.product(
            [row[0] for row in TOOL.load('verify-login-prepare-context').SCENARIOS],
            (0,1,2,3,4,255),(False,True),(0,1),(0x55,0xaa))]
        r=dict(source_sha256='a'*64,scope=TOOL.SCOPE,method='bounded_native',network_used=False,profile_activated=False,
            runtime_activated=False,proof=c['transfer_proof'],context_sha256='c'*64,cases=cases,native_sdk_used=False,native_metadata_used=False)
        return c,r

    def test_only_two_roots_and_no_optional_native_sdk_fields(self):
        c=dict(prepare='0x1000',constructor='0x2000');self.assertEqual(TOOL.roots(c),{4096,8192})
        for key in ('native_sdk','native_metadata','function_budget'):
            with self.subTest(key=key),self.assertRaises(ValueError):TOOL.roots(dict(c,**{key:{}}))
        with self.assertRaises(ValueError):TOOL.roots(dict(c,constructor='0x1000'))

    def test_native_report_requires_672_cases_and_false_sdk_metadata_scope(self):
        c,r=self.fixture();TOOL.report_valid(r,c,'c'*64)
        for change in (dict(scope='full-login'),dict(cases=[]),dict(cases=[dict(guards=False)]*672),dict(native_sdk_used=True),
                dict(native_metadata_used=True),dict(runtime_activated=True),dict(network_used=True)):
            with self.subTest(change=tuple(change)),self.assertRaises(ValueError):TOOL.report_valid({**r,**change},c,'c'*64)

    def test_native_report_rejects_duplicate_and_missing_matrix_cases(self):
        c,r=self.fixture()
        cases=copy.deepcopy(r['cases']);cases[-1]=copy.deepcopy(cases[0])
        self.assertEqual(len(cases),672)
        with self.assertRaisesRegex(ValueError,'matrix is incomplete or duplicated'):
            TOOL.report_valid({**r,'cases':cases},c,'c'*64)
        with self.assertRaises(ValueError):TOOL.report_valid({**r,'cases':r['cases'][:-1]},c,'c'*64)

    def test_native_report_rejects_unrecognized_matrix_dimension_value(self):
        c,r=self.fixture()
        for field,value in (('scenario','unknown'),('selector',5),('empty',None),('send_return',2),('poison',0)):
            cases=copy.deepcopy(r['cases']);cases[0][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'matrix is incomplete or duplicated'):
                TOOL.report_valid({**r,'cases':cases},c,'c'*64)

    def test_same_target_reuses_published_context_without_new_transfer(self):
        c,_=self.fixture();args=SimpleNamespace(root='root',knowledge='definitions')
        with patch.object(TOOL,'load',return_value=SimpleNamespace(read=lambda _:{})),patch.object(TOOL,'published_contexts',return_value=[(Path('ctx'),c,4)]),\
                patch.object(TOOL,'validate') as validate,patch.object(TOOL,'checked',return_value={'same':'proof'}),\
                patch.object(TOOL,'planned',return_value='reused') as planned,patch.object(TOOL,'transfer',side_effect=AssertionError('No same-target transfer')):
            self.assertEqual(TOOL.discover(None,args,'a'*64),'reused');validate.assert_called_once();planned.assert_called_once_with(c,{'same':'proof'})

    def test_plain_removes_export_pointer_fields_without_mutating_context(self):
        c,_=self.fixture();c.update(exports={'run':'hash'},release_id='next')
        value=TOOL.plain(c)
        self.assertNotIn('transfer_proof',value);self.assertNotIn('exports',value);self.assertNotIn('release_id',value)
        self.assertIn('exports',c)

    def test_publication_rejects_wrong_scope_before_replacing_index(self):
        c,r=self.fixture();declaration=dict(context=dict(path='ctx',sha256='c'*64));outcome=dict(state='passed',report='report',sha256='d'*64)
        workflow=SimpleNamespace(atomic=Mock())
        with tempfile.TemporaryDirectory() as temporary:
            args=SimpleNamespace(root=Path(temporary),knowledge=Path(temporary))
            with patch.object(TOOL,'validate'),patch.object(TOOL,'checked',side_effect=lambda root,item,category:c if category=='generated-native-contexts' else {**r,'native_sdk_used':True}):
                with self.assertRaises(ValueError):TOOL.publish(None,args,'a'*64,declaration,outcome)
            workflow.atomic.assert_not_called()

    def test_published_contexts_reject_duplicate_source_or_mismatched_semantic_report(self):
        c,r=self.fixture();entry=dict(context=dict(path='ctx',sha256='c'*64),check=dict(path='report',sha256='d'*64),order=1);registry=dict(releases=[])
        with patch.object(TOOL,'checked',side_effect=lambda root,item,category:c if category=='generated-native-contexts' else r):
            self.assertEqual(len(TOOL.published_contexts('root',registry,value=dict(schema=1,contexts=[entry]))),1)
            with self.assertRaises(ValueError):TOOL.published_contexts('root',registry,value=dict(schema=1,contexts=[entry,entry]))
        with patch.object(TOOL,'checked',side_effect=lambda root,item,category:c if category=='generated-native-contexts' else {**r,'cases':[]}):
            with self.assertRaises(ValueError):TOOL.published_contexts('root',registry,value=dict(schema=1,contexts=[entry]))

    def test_proof_cycles_and_changed_schema_stop_before_source_reads(self):
        c,_=self.fixture();args=SimpleNamespace(root=Path('root'))
        with patch.object(TOOL,'checked',return_value={}),patch.object(TOOL,'tools',return_value={}):
            with self.assertRaisesRegex(ValueError,'cycle'):TOOL.validate(None,args,c,{'b'*64})
            with self.assertRaisesRegex(ValueError,'proof fields'):TOOL.validate(None,args,c)


class LoginFixtureBoundaryTests(unittest.TestCase):
    def setUp(self):
        names=list(TOOL.LEAF_SIZES)+['fixture-'+str(i) for i in range(21)]
        self.base=dict(prepare='0x1000',constructor='0x2000',fixtures={name:hex(0x10000+n*0x100) for n,name in enumerate(names)})
        self.current=copy.deepcopy(self.base);self.current['fixtures']={name:hex(int(at,16)+0x100000) for name,at in self.base['fixtures'].items()}
        self.images=[]
        for context in (self.base,self.current):
            values=[int(at,16) for name,at in context['fixtures'].items() if name not in TOOL.LEAF_SIZES]
            image=SimpleNamespace(pe=SimpleNamespace(base=0),roots={at:(at,at+32) for at in values},containing=lambda at,values=values:at if at in values else None)
            self.images.append(image)

    def boundaries(self):
        common=SimpleNamespace(pair_rows=Mock())
        with patch.object(TOOL,'load',return_value=common),patch.object(TOOL,'fixture_leaf',return_value=[]),\
                patch.object(TOOL,'image_bytes',side_effect=lambda image,at,size:b'\xc2\0\0' if size==3 else bytes(size)):
            return TOOL.fixture_boundaries(None,*self.images,self.base,self.current,{})

    def test_bounded_fixture_leaves_are_distinct_from_unwind_roots_and_not_executed(self):
        result=self.boundaries();self.assertEqual(len(result),32)
        self.assertEqual(result['wide_compare']['size'],71)
        self.assertIn('not executed',result['sdk_manager']['scope'])
        self.assertEqual(result['fixture-0']['kind'],'unwind-fixture')

    def test_fixture_aliases_unknown_role_count_and_mid_function_target_are_rejected(self):
        original=copy.deepcopy(self.current)
        self.current['fixtures']['fixture-0']=self.current['prepare']
        with self.assertRaisesRegex(ValueError,'aliases'):self.boundaries()
        self.current=copy.deepcopy(original);self.current['fixtures'].pop('fixture-0')
        with self.assertRaisesRegex(ValueError,'role set'):self.boundaries()
        self.current=copy.deepcopy(original);self.current['fixtures']['fixture-0']=hex(int(self.current['fixtures']['fixture-0'],16)+1)
        with self.assertRaisesRegex(ValueError,'unwind entry'):self.boundaries()


if __name__=='__main__':unittest.main()
