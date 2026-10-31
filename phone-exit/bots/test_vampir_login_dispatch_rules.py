"""Pure source metadata, relocation and zero-initialized TLS bounds."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent/'resource-tools/vampir'
def load(name):
    s=importlib.util.spec_from_file_location(name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
rules=load('login-dispatch-rules')
def seed():return json.loads((HERE/'knowledge/native-contexts/login-dispatch-11322.json').read_text('utf-8'))


class DispatchRuleTests(unittest.TestCase):
    def test_reference_has_29_whole_roots_12_leaves_and_no_semantic_proof(self):
        c=seed();self.assertEqual(len(rules.roots(c)),29);self.assertEqual(len(c['leaves']),12)
        self.assertEqual(c['format'],rules.REFERENCE);self.assertNotIn('transfer_proof',c)
        self.assertEqual((c['owner_bytes'],c['packet_allocation_bytes'],c['framing_minimum']),(80,344,5))

    def test_layout_or_framing_relaxation_is_rejected(self):
        for key,val in [('framing_minimum',4),('owner_bytes',72),('packet_allocation_bytes',352),('node_bytes',True),('verify_whole_exports',1)]:
            c=seed();c[key]=val
            with self.subTest(key=key),self.assertRaises(ValueError):rules.roots(c)

    def test_malformed_cookie_and_object_fields_are_specific_value_errors(self):
        for value in (None,1,True,{},'short'):
            c=seed();c['source_initial']['cookie']=value
            with self.subTest(value=value),self.assertRaises(ValueError):rules.roots(c)
        for key in ('globals','literals','functions','source_initial'):
            c=seed();c[key]=None
            with self.subTest(key=key),self.assertRaises(ValueError):rules.roots(c)

    def test_root_alias_leaf_shadow_and_unreviewed_fields_are_rejected(self):
        for role in ('root','leaf','field','pointer'):
            c=seed()
            if role=='root':c['functions']['lookup']=c['functions']['dispatch']
            if role=='leaf':c['leaves'][c['functions']['dispatch']]='c3'
            if role=='field':c['function_budget']=64
            if role=='pointer':c['composition_context']['sha256']='short'
            with self.subTest(role=role),self.assertRaises(ValueError):rules.roots(c)

    def test_native_input_utf8_and_diagnostic_wrapper_are_distinct_addresses(self):
        c=seed();self.assertNotEqual(c['functions']['composition.input.utf8_convert'],'0x141446650')
        self.assertEqual(c['source_initial']['archive_flags'],'01000000')

    def test_tls_virtual_tail_is_distinct_from_file_backed_data(self):
        section=dict(name='.data',rva=100,size=100,raw=80,raw_size=20)
        def offset(rva):raise ValueError('not backed')
        image=SimpleNamespace(pe=SimpleNamespace(base=1000,sections=[section]),offset=offset)
        self.assertEqual(rules.virtual_span(image,1140)['size_bytes'],4)
        for at in (1110,1198):
            with self.assertRaises(ValueError):rules.virtual_span(image,at)
        image.offset=lambda _:0
        with self.assertRaisesRegex(ValueError,'file-backed'):rules.virtual_span(image,1140)

    def test_cleanup_leaf_can_move_independently_of_its_declared_tail(self):
        native=load('build-native-entry-code')
        def row(at,target):
            raw=b'\xe9'+struct.pack('<i',target-at-5)
            return [dict(address=at,bytes=raw.hex(),mnemonic='jmp',operands=hex(target),call=False,branch=True,direct_target=target,rip_references=[])]
        old,new=row(0x1000,0x2000),row(0x5000,0x9000)
        mapping={0x2000:0x9000};rules.pair_declared_leaf(native,old,new,{0x2000},mapping)
        self.assertEqual(mapping[0x1000],0x5000)
        with self.assertRaises(ValueError):rules.pair_declared_leaf(native,old,new,set(),{})
        with self.assertRaises(ValueError):rules.pair_declared_leaf(native,old,new,{0x2000},{0x2000:0x8000})

    def test_empty_ansi_argument_survives_intervening_stores_26_bytes_before_call(self):
        native=load('build-native-entry-code');comp={'functions':{'packet.constructor':'0x1000'}}
        container={'functions':{'string_constructor':'0x3000'}}
        rows=[dict(address=0x1000,bytes='488d1500000000',mnemonic='lea',operands='rdx, [rip]',rip_references=[0x2000],call=False,direct_target=None),
            dict(address=0x1007,bytes='894310',mnemonic='mov',operands='dword ptr [rbx + 0x10], eax',rip_references=[],call=False,direct_target=None),
            dict(address=0x101a,bytes='e800000000',mnemonic='call',operands='0x3000',rip_references=[],call=True,direct_target=0x3000)]
        bindings=SimpleNamespace(rows=lambda *_:rows)
        with patch.object(rules,'data',return_value=b'\0'):
            self.assertEqual(rules.packet_empty_source(native,bindings,None,comp,container),dict(address='0x2000',bytes='00'))
            rows[1].update(bytes='31d2',mnemonic='xor',operands='edx, edx')
            with self.assertRaisesRegex(ValueError,'overwritten'):rules.packet_empty_source(native,bindings,None,comp,container)
        with patch.object(rules,'data',return_value=b'x'):
            with self.assertRaises(ValueError):rules.packet_empty_source(native,bindings,None,comp,container)


if __name__=='__main__':unittest.main()
