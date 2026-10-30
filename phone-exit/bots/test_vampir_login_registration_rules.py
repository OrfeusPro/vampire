"""Registration binds exact static allocation/control flow and one helper root."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch
from test_vampir_update_contracts import load

RULE = load('login-registration-rules')


def context():
    return json.loads((RULE.HERE/'knowledge/native-contexts/login-registration-11318.json').read_text('utf-8'))


def native_and_image(c):
    native = load('build-native-entry-code')
    at = int(c['window']['address'], 16); raw = bytearray.fromhex(c['window']['bytes']); b = c['bindings']
    words = {int(b['handler_table'],16)+0x10: int(b['handler'],16).to_bytes(8,'little')}
    class Image:
        containing = lambda self, value: ('owner',) if at <= value < at+75 else None
        roots = {('owner',):(int(b['owner'],16),0,0)}
        pe = SimpleNamespace(base=0)
    image=Image()
    def data(owner,address,size):
        if at<=address<at+75:return bytes(raw[address-at:address-at+size])
        return words[address][:size]
    utility=SimpleNamespace(concrete=Mock())
    old_load=RULE.load
    def module(name): return utility if name=='version-system-transfer-rules' else old_load(name)
    return native,image,raw,data,module


class RegistrationRulesTests(unittest.TestCase):
    def test_legacy_projection_is_explicit_static_source_and_one_helper_plus_id_leaf(self):
        c=context()
        self.assertEqual(RULE.roots(c),{int(c['bindings']['register'],16)})
        self.assertEqual((c['packet_bytes'],c['packet_allocation_bytes']),(320,320))
        self.assertEqual(c['leaves'],{c['bindings']['id_getter']:'b804000000c3'})
        self.assertEqual(c,json.loads(json.dumps(c)))

    def test_current_scope_distinguishes_harness_extent_from_real_allocation(self):
        c=context();c.update(format=RULE.CURRENT,packet_bytes=352,packet_allocation_bytes=344,
            nested_context=dict(path='nested',sha256='a'*64),full_handler_context=dict(path='handler',sha256='b'*64))
        self.assertEqual(len(RULE.roots(c)),1)
        for field,value in (('packet_bytes',344),('packet_allocation_bytes',352),('schema',True)):
            with self.subTest(field=field),self.assertRaises(ValueError):RULE.roots(dict(c,**{field:value}))

    def test_schema_rejects_native_scope_expansion_aliases_and_wrong_legacy_source(self):
        c=context()
        for key in ('native_dispatch','native_window','function_budget','budget_scope','helpers'):
            with self.subTest(key=key),self.assertRaises(ValueError):RULE.roots(dict(c,**{key:True}))
        bad=copy.deepcopy(c);bad['source_sha256']='a'*64
        with self.assertRaises(ValueError):RULE.roots(bad)
        bad=copy.deepcopy(c);bad['fixtures']['log']=bad['functions']['register']
        with self.assertRaises(ValueError):RULE.roots(bad)
        bad=copy.deepcopy(c);bad['fixtures']['log']=bad['fixtures']['free']
        with self.assertRaises(ValueError):RULE.roots(bad)

    def test_window_hash_id_bytes_and_typed_literals_are_not_optional(self):
        c=context()
        for change in ('window','id','literal'):
            bad=copy.deepcopy(c)
            if change=='window':bad['window']['sha256']='0'*64
            elif change=='id':bad['leaves'][bad['bindings']['id_getter']]='b802000000c3'
            else:bad['literals']['log_format']['bytes']='00'
            with self.subTest(change=change),self.assertRaises(ValueError):RULE.roots(bad)

    def test_source_window_preserves_21_instructions_three_arguments_and_two_null_branches(self):
        c=context();n,image,raw,data,module=native_and_image(c)
        with patch.object(RULE,'data',side_effect=data),patch.object(RULE,'load',side_effect=module),patch.object(RULE,'fixture_boundary',return_value={}):
            found,span=RULE.window(n,image,int(c['window']['address'],16))
        self.assertEqual(found['register'],c['bindings']['register'])
        self.assertEqual(found['packet_allocation_bytes'],320)
        self.assertEqual(span,c['window'])

    def test_window_rejects_changed_argument_branch_and_allocation_against_source_bindings(self):
        for index in (16,29,63,66,69):
            c=context();n,image,raw,data,module=native_and_image(c);raw[index]^=1
            with self.subTest(index=index),patch.object(RULE,'data',side_effect=data),patch.object(RULE,'load',side_effect=module),patch.object(RULE,'fixture_boundary',return_value={}):
                with self.assertRaises(ValueError):RULE.window(n,image,int(c['window']['address'],16))
        c=context();n,image,raw,data,module=native_and_image(c)
        expected={key:c['bindings'][key] for key in ('owner','allocate','packet_constructor','register','handler_table','handler')}
        expected['packet_allocation_bytes']=352
        with patch.object(RULE,'data',side_effect=data),patch.object(RULE,'load',side_effect=module),patch.object(RULE,'fixture_boundary',return_value={}):
            with self.assertRaisesRegex(ValueError,'allocation differs'):RULE.window(n,image,int(c['window']['address'],16),expected)

    def test_source_window_is_contained_in_one_owner_range(self):
        c=context();n,image,raw,data,module=native_and_image(c)
        image.containing=lambda value:('owner',) if value==int(c['window']['address'],16) else ('other',)
        with patch.object(RULE,'data',side_effect=data),patch.object(RULE,'load',side_effect=module),patch.object(RULE,'fixture_boundary',return_value={}):
            with self.assertRaisesRegex(ValueError,'owner range'):RULE.window(n,image,int(c['window']['address'],16))

    def test_constructor_byte_occurrence_requires_exact_unique_window(self):
        # The PE scan is only a candidate provider; window() grants identity.
        target=0x1500; raw=bytearray(80);raw[51]=0xe8;raw[52:56]=(target-(0x1000+51)-5).to_bytes(4,'little',signed=True)
        image=SimpleNamespace(data=bytes(raw),pe=SimpleNamespace(sections=[dict(name='.text',raw=0,raw_size=len(raw))],address=lambda off:0x1000+off))
        with patch.object(RULE,'window',return_value=({'packet_constructor':hex(target)},{})) as check:
            self.assertEqual(RULE.find_window(None,image,target)[0]['packet_constructor'],hex(target))
            check.assert_called_once_with(None,image,0x1000)
        with patch.object(RULE,'window',side_effect=ValueError('wrong boundary')):
            with self.assertRaisesRegex(ValueError,'missing or ambiguous'):RULE.find_window(None,image,target)
        raw.extend(bytearray(80));raw[131]=0xe8;raw[132:136]=(target-(0x1000+131)-5).to_bytes(4,'little',signed=True)
        image.data=bytes(raw);image.pe.sections[0]['raw_size']=len(raw)
        with patch.object(RULE,'window',return_value=({},{})):
            with self.assertRaisesRegex(ValueError,'missing or ambiguous'):RULE.find_window(None,image,target)

    def test_static_context_does_not_accept_changed_fixture_data_or_calls(self):
        c=context();n,image,raw,data,module=native_and_image(c)
        parts=({},c['fixtures'],c['globals'],c['literals'],c['fixture_boundaries'])
        with patch.object(RULE,'window',return_value=({},c['window'])),patch.object(RULE,'helper_parts',return_value=parts),patch.object(RULE,'calls',return_value={}):
            with self.assertRaisesRegex(ValueError,'typed source'):RULE.validate_static(None,None,None,c)

    def test_dependency_pointer_fields_require_distinct_exact_full_hashes(self):
        c=context();c.update(format=RULE.CURRENT,packet_bytes=352,packet_allocation_bytes=344,
            nested_context=dict(path='nested',sha256='a'*64),full_handler_context=dict(path='handler',sha256='b'*64))
        for bad in (dict(path='nested',sha256='short'),dict(path='',sha256='a'*64),dict(path='nested',sha256='a'*64,extra=True)):
            with self.assertRaises(ValueError):RULE.roots(dict(c,nested_context=bad))
        with self.assertRaisesRegex(ValueError,'dependencies alias'):RULE.roots(dict(c,full_handler_context=c['nested_context']))

    def test_export_is_exact_one_root_and_whole_coverage(self):
        c=context();at=int(c['bindings']['register'],16);row=dict(address=at,bytes='c3')
        report=dict(new_source_sha256=c['source_sha256'],functions=[dict(address=hex(at),decompilation_completed=True,
            block_coverage_complete=True,direct_flow_coverage_complete=True,instructions=[dict(address=hex(at),bytes='c3')])])
        normalizer=SimpleNamespace(normalize_function=Mock())
        for change in (None,'missing','duplicate','extra','flag','hash','source'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as directory:
                value=copy.deepcopy(report)
                if change=='missing':value['functions']=[]
                elif change=='duplicate':value['functions'][0]['instructions']*=2
                elif change=='extra':value['functions'][0]['instructions'].append(dict(address=hex(at+1),bytes='90'))
                elif change=='flag':value['functions'][0]['block_coverage_complete']=False
                elif change=='source':value['new_source_sha256']='1'*64
                p=Path(directory)/'ghidra/request-exports'/c['source_sha256']/'run-fixture/details.json';p.parent.mkdir(parents=True);p.write_text(json.dumps(value))
                c['exports']={'run-fixture':hashlib.sha256(p.read_bytes()).hexdigest() if change!='hash' else '0'*64}
                with patch.object(RULE,'validate_static',return_value=[row]),patch.object(RULE,'load',return_value=normalizer):
                    if change is None:RULE.export_coverage(directory,c,None,None,None)
                    else:
                        with self.assertRaises(ValueError):RULE.export_coverage(directory,c,None,None,None)


if __name__=='__main__':unittest.main()
