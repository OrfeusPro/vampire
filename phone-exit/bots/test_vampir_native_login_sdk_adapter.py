"""Source/layout and receipt admission for the bounded Login SDK adapter."""
import copy
import hashlib
import itertools
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from test_vampir_update_contracts import load

TOOL=load('update-native-login-sdk')


def context():
    value=json.loads((TOOL.HERE/'knowledge/native-contexts/login-prepare-sdk-11320.json').read_text('utf-8'))
    value.update(family=TOOL.FAMILY,layout=copy.deepcopy(TOOL.LAYOUT),transfer_proof=dict(path='proof',sha256='b'*64))
    return value


def report(value):
    fields=('scenario','selector','empty','send_return','poison','cache_case')
    cases=[dict(zip(fields,row),guards=True) for row in itertools.product(
        [row[0] for row in load('verify-login-prepare-context').SCENARIOS],
        (0,1,2,3,4,255),(False,True),(0,1),(0x55,0xaa),('warm','resolve','absent'))]
    return dict(source_sha256=value['source_sha256'],scope=TOOL.SCOPE,method='bounded_native',network_used=False,
        profile_activated=False,runtime_activated=False,proof=value['transfer_proof'],context_sha256='c'*64,
        native_sdk_used=True,native_metadata_used=False,metadata_fields=value['native_sdk']['metadata']['fields'],
        cases=cases)


class LoginSdkScopeTests(unittest.TestCase):
    def test_reviewed_roles_are_exactly_five_roots_and_six_native_leaves(self):
        c=context();self.assertEqual(len(TOOL.roots(c)),5)
        self.assertEqual(len(c['native_sdk']['leaves']),6)

    def test_optional_metadata_and_function_budget_cannot_expand_scope(self):
        for key in ('native_metadata','function_budget'):
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'scope'):
                TOOL.roots(dict(context(),**{key:{}}))

    def test_native_role_set_cannot_hide_an_extra_or_duplicate_role(self):
        for mutation in (lambda s:s['native_names'].append('sdk_mode'),lambda s:s['native_names'].append('other'),
                         lambda s:s['native_names'].remove('sdk_value'),lambda s:s['fixtures'].update(other='0x123')):
            c=context();mutation(c['native_sdk'])
            with self.assertRaisesRegex(ValueError,'scope'):TOOL.roots(c)

    def test_getters_and_returning_leaves_cannot_alias(self):
        c=context();c['native_sdk']['functions']['sdk_value']=c['native_sdk']['functions']['sdk_mode']
        with self.assertRaisesRegex(ValueError,'alias'):TOOL.roots(c)
        c=context();c['native_sdk']['functions']['sdk_mode']=c['prepare']
        with self.assertRaisesRegex(ValueError,'alias'):TOOL.roots(c)

    def test_leaf_role_must_still_match_its_direct_base_caller(self):
        c=context();c['fixtures']['sdk_manager']='0x1234'
        with self.assertRaisesRegex(ValueError,'fixture links'):TOOL.roots(c)
        c=context();a,b=c['fixtures']['sdk_mode'],c['fixtures']['sdk_value']
        c['fixtures'].update(sdk_mode=b,sdk_value=a)
        with self.assertRaisesRegex(ValueError,'getter role'):TOOL.roots(c)

    def test_sdk_fixture_hooks_cannot_override_outer_hook_or_execute_code(self):
        for target in ('prepare','outer','leaf','memcpy','inner'):
            c=context();values=dict(prepare=c['prepare'],outer=c['fixtures']['wide_string'],
                leaf=next(iter(c['native_sdk']['leaves'])),memcpy=c['helpers']['memcpy'],inner=c['native_sdk']['fixtures']['main_store'])
            c['native_sdk']['fixtures']['mode_text']=values[target]
            with self.subTest(target=target),self.assertRaisesRegex(ValueError,'aliases'):TOOL.roots(c)

    def test_plain_strips_only_mutable_receipts_and_exports_without_mutation(self):
        c=context();c['native_sdk']['exports']={'run-sdk':'hash'};c['release_id']='new'
        value=TOOL.plain(c)
        self.assertNotIn('exports',value);self.assertNotIn('exports',value['native_sdk'])
        self.assertNotIn('transfer_proof',value);self.assertNotIn('release_id',value)
        self.assertIn('exports',c);self.assertIn('exports',c['native_sdk'])

    def test_base_transfer_is_reconstructed_without_sdk_or_newer_family_layout(self):
        c=context();base=TOOL.base_context(c)
        for key in ('native_sdk','exports','transfer_proof','release_id','family','layout'):
            self.assertNotIn(key,base)
        self.assertEqual(base['prepare'],c['prepare']);self.assertEqual(base['fixtures'],c['fixtures'])
        base['fixtures']['sdk_mode']='0x1';self.assertNotEqual(base['fixtures'],c['fixtures'])


class LoginSdkLiteralAndLeafTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.native=load('build-native-entry-code')

    def test_leaf_hash_and_actual_source_bytes_are_both_required(self):
        raw=bytes.fromhex('488b0519e0fd05c3');spec=dict(bytes=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
        with patch.object(TOOL,'image_bytes',return_value=raw):
            rows=TOOL.leaf_rows(self.native,None,0x1000,spec,baseline=True)
            self.assertEqual(rows[-1]['mnemonic'],'ret');self.assertEqual(rows[0]['rip_references'],[0x1007+0x5fde019])
            with self.assertRaisesRegex(ValueError,'hash'):TOOL.leaf_rows(self.native,None,0x1000,dict(spec,sha256='0'*64))
        with patch.object(TOOL,'image_bytes',return_value=b'\x90'*7+b'\xc3'):
            with self.assertRaisesRegex(ValueError,'baseline leaf changed'):TOOL.leaf_rows(self.native,None,0x1000,spec,baseline=True)

    def test_leaf_cannot_call_branch_truncate_or_fall_through(self):
        for raw in (b'\xe8\0\0\0\0\xc3',b'\xeb\0\xc3',b'\x90',b'\x48'):
            spec=dict(bytes=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
            with self.subTest(raw=raw.hex()),patch.object(TOOL,'image_bytes',return_value=raw),self.assertRaisesRegex(ValueError,'complete return'):
                TOOL.leaf_rows(self.native,None,0x1000,spec)

    def test_wide_literals_are_bounded_utf16_with_explicit_terminator(self):
        raw='hello'.encode('utf-16le')+b'\0\0'
        with patch.object(TOOL,'image_bytes',side_effect=lambda image,at,size:raw[at:at+size]):
            self.assertEqual(TOOL.wide_literal(None,0),('hello',raw))
        with patch.object(TOOL,'image_bytes',return_value=b'A\0'),self.assertRaisesRegex(ValueError,'bound'):
            TOOL.wide_literal(None,0)

    def fields_fixture(self):
        rows=[];names={};wide=0x100;consumer=0x200
        for i in range(27):
            at=0x1000+i*8;names[at]='I_World' if i in (7,20) else 'I_Field'+str(i)
            rows.append(dict(address=0x10000+i*32,rip_references=[at],mnemonic='lea',operands='rdx, [rip + 1]',direct_target=None))
            rows.extend(dict(address=0x10000+i*32+j,rip_references=[],mnemonic='call' if j in (2,5) else 'mov',operands='',
                direct_target=wide if j==2 else consumer if j==5 else None) for j in range(1,6))
        return rows,names,wide,consumer

    def test_metadata_preserves_duplicate_keys_and_exact_consumer_call_sites(self):
        rows,names,wide,consumer=self.fields_fixture();bindings=SimpleNamespace(rows=lambda *args:rows)
        with patch.object(TOOL,'image_bytes',return_value=b'I\0_\0'),patch.object(TOOL,'wide_literal',side_effect=lambda _,at:(names[at],b'')):
            fields=TOOL.metadata_fields(None,bindings,None,0x900,wide,consumer)
            self.assertEqual(len(fields),27);self.assertEqual([f['key'] for f in fields].count('I_World'),2)
            self.assertEqual(fields[0]['call_site'],hex(rows[5]['address']))
            rows[5]['direct_target']=0x201
            with self.assertRaisesRegex(ValueError,'call linkage'):TOOL.metadata_fields(None,bindings,None,0x900,wide,consumer)

    def test_incomplete_static_metadata_projection_is_a_blocker(self):
        rows,names,wide,consumer=self.fields_fixture();bindings=SimpleNamespace(rows=lambda *args:rows[:-6])
        with patch.object(TOOL,'image_bytes',return_value=b'I\0_\0'),patch.object(TOOL,'wide_literal',side_effect=lambda _,at:(names[at],b'')),self.assertRaisesRegex(ValueError,'field count'):
            TOOL.metadata_fields(None,bindings,None,0x900,wide,consumer)

    def test_only_exact_reviewed_cache_dispatch_thunk_can_lack_unwind(self):
        image=SimpleNamespace(containing=lambda at:None)
        thunk=bytes.fromhex('488b0148ffa010040000')+b'\xcc'*6
        with patch.object(TOOL,'image_bytes',return_value=thunk):
            rows=TOOL.inner_boundaries(image,image,dict(cache_resolve='0x1000'),dict(cache_resolve='0x2000'))
            self.assertEqual(rows['cache_resolve']['kind'],'fixture-dispatch-thunk')
            with self.assertRaisesRegex(ValueError,'thunk changed'):
                TOOL.inner_boundaries(image,image,dict(cache_resolve='0x1000'),dict(cache_resolve='0x2001'))
            with self.assertRaisesRegex(ValueError,'unwind boundary'):
                TOOL.inner_boundaries(image,image,dict(main_store='0x1000'),dict(main_store='0x2000'))
        with patch.object(TOOL,'image_bytes',return_value=thunk[:-1]+b'\x90'),self.assertRaisesRegex(ValueError,'thunk changed'):
            TOOL.inner_boundaries(image,image,dict(cache_resolve='0x1000'),dict(cache_resolve='0x2000'))


class LoginSdkAdmissionTests(unittest.TestCase):
    def test_complete_2016_case_matrix_is_not_an_online_admission(self):
        c=context();r=report(c);TOOL.report_valid(r,c,'c'*64)
        self.assertEqual(len(r['cases']),2016);self.assertIs(r['runtime_activated'],False)

    def test_source_context_proof_and_all_guard_results_are_checked(self):
        c=context();r=report(c)
        changes=[dict(source_sha256='d'*64),dict(context_sha256='d'*64),dict(proof={}),dict(scope='full-entry'),
            dict(method='synthetic'),dict(cases=r['cases'][:-1]),dict(cases=[dict(guards=False,cache_case='warm')]*2016)]
        for key in ('network_used','profile_activated','runtime_activated','native_metadata_used'):changes.append({key:True})
        changes.extend([dict(native_sdk_used=False),dict(metadata_fields=list(reversed(r['metadata_fields'])))])
        for changed in changes:
            with self.subTest(changed=tuple(changed)),self.assertRaises(ValueError):TOOL.report_valid({**r,**changed},c,'c'*64)

    def test_all_three_cache_states_are_required(self):
        c=context();r=report(c);r['cases']=[dict(guards=True,cache_case='warm')]*2016
        with self.assertRaises(ValueError):TOOL.report_valid(r,c,'c'*64)

    def test_count_with_duplicated_matrix_rows_cannot_publish(self):
        c=context();r=report(c);r['cases'][-1]=copy.deepcopy(r['cases'][0])
        self.assertEqual(len(r['cases']),2016)
        with self.assertRaisesRegex(ValueError,'matrix'):TOOL.report_valid(r,c,'c'*64)

    def test_same_sha_reuses_original_proof_instead_of_self_transfer(self):
        c=context();args=SimpleNamespace(root='root',knowledge='defs')
        with patch.object(TOOL,'load',return_value=SimpleNamespace(read=lambda _:{})),patch.object(TOOL,'published_contexts',return_value=[(Path('ctx'),c,3)]),\
                patch.object(TOOL,'validate') as verify,patch.object(TOOL,'checked',return_value={'original':'proof'}),\
                patch.object(TOOL,'planned',return_value='reused') as planned,patch.object(TOOL,'transfer',side_effect=AssertionError('No self-transfer')):
            self.assertEqual(TOOL.discover(None,args,c['source_sha256']),'reused')
            verify.assert_called_once();planned.assert_called_once_with(c,{'original':'proof'})

    def test_newer_base_role_cannot_replace_independent_sdk_baseline_proof(self):
        c=context();base=TOOL.base_context(c);api=SimpleNamespace(transfer=Mock(return_value=(dict(prepare='0x1'),{})),plain=lambda c:c)
        with patch.object(TOOL,'load',return_value=api),self.assertRaisesRegex(ValueError,'base caller differs'):
            TOOL.transfer(None,None,None,None,c,dict(prepare='0x2'),{})
        api.transfer.assert_called_once();self.assertEqual(api.transfer.call_args.args[4],base)

    def test_published_index_needs_matching_family_unique_sha_and_real_report(self):
        c=context();r=report(c);row=dict(context=dict(path='ctx',sha256='c'*64),check=dict(path='report',sha256='d'*64),order=1)
        registry=dict(releases=[dict(source_sha256=c['source_sha256'],order=2)])
        with patch.object(TOOL,'checked',side_effect=lambda root,item,category:c if category=='generated-native-contexts' else r):
            self.assertEqual(TOOL.published_contexts('root',registry,value=dict(schema=1,contexts=[row]))[0][2],2)
            for value in (dict(schema=1,contexts=[row,row]),dict(schema=2,contexts=[row])):
                with self.assertRaises(ValueError):TOOL.published_contexts('root',registry,value=value)
            c['family']='login-prepare'
            with self.assertRaisesRegex(ValueError,'source/family'):TOOL.published_contexts('root',registry,value=dict(schema=1,contexts=[row]))

    def test_failed_report_cannot_change_an_existing_published_index(self):
        c=context();r=report(c);r['native_metadata_used']=True
        declaration=dict(context=dict(path='ctx',sha256='c'*64));outcome=dict(state='passed',report='report',sha256='d'*64)
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'knowledge'/TOOL.INDEX/'index.json';p.parent.mkdir(parents=True);p.write_text('existing')
            args=SimpleNamespace(root=Path(directory),knowledge=Path(directory))
            with patch.object(TOOL,'validate'),patch.object(TOOL,'checked',side_effect=lambda root,item,category:c if category=='generated-native-contexts' else r),self.assertRaises(ValueError):
                TOOL.publish(None,args,c['source_sha256'],declaration,outcome)
            self.assertEqual(p.read_text(),'existing')

    def test_changed_proof_or_cycle_stops_before_source_access(self):
        c=context();args=SimpleNamespace(root=Path('root'))
        with patch.object(TOOL,'checked',return_value={}),patch.object(TOOL,'tools',return_value={}):
            with self.assertRaisesRegex(ValueError,'cycle'):TOOL.validate(None,args,c,{'b'*64})
            with self.assertRaisesRegex(ValueError,'proof fields'):TOOL.validate(None,args,c)


if __name__=='__main__':unittest.main()
