"""Admit only exact integrated roles and typed virtual PE providers."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent/'resource-tools/vampir'
spec=importlib.util.spec_from_file_location('state_flow_rules',HERE/'login-state-flow-rules.py')
rules=importlib.util.module_from_spec(spec);spec.loader.exec_module(rules)


def seed():return json.loads((HERE/'knowledge/native-contexts/login-state-flow-11322.json').read_text('utf-8'))


class StateFlowRulesTests(unittest.TestCase):
    def test_bootstrap_inventory_has_no_integrated_semantic_claim(self):
        c=seed();self.assertEqual(len(rules.roots(c)),33);self.assertEqual(len(c['leaves']),14)
        self.assertEqual(c['format'],rules.REFERENCE);self.assertNotIn('transfer_proof',c)
        self.assertTrue(all(c[k+'_context']['sha256'] for k in ('dispatch','post_state','continuation')))

    def test_scope_relaxations_or_provider_aliases_are_rejected(self):
        for mutation in ('budget','framing','constructor','getter','unknown','overlap'):
            c=seed()
            if mutation=='budget':c['function_budget']=64
            if mutation=='framing':c['framing_minimum']=4
            if mutation=='constructor':c['functions']['continuation.constructor']=c['functions']['continuation.reset']
            if mutation=='getter':c['leaves'][c['state_bindings']['post_getter']]='c3'
            if mutation=='unknown':c['functions']['dispatch.fake']=c['functions']['dispatch.lookup']
            if mutation=='overlap':c['virtual_globals']['continuation_flag']['address']=c['virtual_globals']['continuation_singleton']['address']
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):rules.roots(c)

    def test_width_and_object_extent_types_fail_closed(self):
        for key in rules.SIZES:
            for value in (None,True,0,rules.SIZES[key]+8):
                c=seed();c[key]=value
                with self.subTest(key=key,value=value),self.assertRaises(ValueError):rules.roots(c)
        for width in (True,2,16,None):
            c=seed();c['virtual_globals']['continuation_flag']['size_bytes']=width
            with self.subTest(width=width),self.assertRaises(ValueError):rules.roots(c)

    def test_child_identity_and_strict_fields_are_pinned(self):
        for role in ('dispatch','post_state','continuation'):
            c=seed();c[role+'_context']['sha256']='short'
            with self.subTest(role=role),self.assertRaises(ValueError):rules.roots(c)
        for key in ('functions','state_bindings','virtual_globals','source_initial'):
            c=seed();c[key]=None
            with self.subTest(key=key),self.assertRaises(ValueError):rules.roots(c)

    def test_virtual_tail_uses_full_width_and_never_file_bytes(self):
        section=dict(name='.data',rva=100,raw=80,raw_size=20,size=100)
        def offset(rva):raise ValueError('virtual')
        image=SimpleNamespace(pe=SimpleNamespace(base=1000,sections=[section]),offset=offset)
        self.assertEqual(rules.virtual_span(image,1199,1)['size_bytes'],1)
        self.assertEqual(rules.virtual_span(image,1192,8)['span'],section)
        for at,width in ((1119,1),(1199,4),(1193,8),(1140,True),(1140,2)):
            with self.subTest(at=at,width=width),self.assertRaises(ValueError):rules.virtual_span(image,at,width)
        image.offset=lambda _:0
        with self.assertRaisesRegex(ValueError,'file-backed'):rules.virtual_span(image,1140,8)

    def test_zero_padded_duplicate_leaf_cannot_hide_a_missing_role(self):
        c=seed();at=next(k for k in c['leaves'] if k not in c['state_bindings'].values())
        raw=c['leaves'].pop(at);other=next(iter(c['leaves']))
        c['leaves']['0x0'+other[2:]]=raw
        with self.assertRaisesRegex(ValueError,'alias'):rules.roots(c)

    def test_handler_preserves_getter_object_and_uses_its_actual_vtable_register(self):
        rows=[dict(address=0x1000),dict(address=0x13be,call=True,direct_target=0x2000),
            dict(address=0x13c3,call=True,direct_target=0x3000),dict(address=0x13c8,bytes='488bc8'),
            dict(address=0x13cb,bytes='488b10'),dict(address=0x13ce,operands='qword ptr [rdx + 0x28]')]
        rules.handler_links(rows,0x2000,0x3000)
        for offset,key,value in ((3,'bytes','488bd0'),(4,'bytes','488b00'),(5,'operands','qword ptr [rax + 0x28]')):
            wrong=copy.deepcopy(rows);wrong[offset][key]=value
            with self.subTest(offset=offset),self.assertRaises(ValueError):rules.handler_links(wrong,0x2000,0x3000)


if __name__=='__main__':unittest.main()
