"""Exact handoff inventory, fixture boundaries and virtual-tail source inputs."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent/'resource-tools/vampir'
spec=importlib.util.spec_from_file_location('handoff_rules',HERE/'login-send-handoff-rules.py')
rules=importlib.util.module_from_spec(spec);spec.loader.exec_module(rules)


def seed():return json.loads((HERE/'knowledge/native-contexts/login-send-handoff-11322.json').read_text('utf-8'))


class HandoffRulesTests(unittest.TestCase):
    def test_exact_reference_inventory_excludes_packet_writer(self):
        c=seed();self.assertEqual(len(rules.roots(c)),12);self.assertEqual(len(c['leaves']),7)
        self.assertEqual(c['format'],rules.REFERENCE);self.assertNotIn('transfer_proof',c)
        self.assertNotIn('0x1456e8520',c['functions'].values())
        self.assertEqual(c['sender']['virtual_slot'],56)

    def test_layout_fifth_argument_and_slot_cannot_be_relaxed(self):
        for key,value in (('packet_bytes',352),('session_bytes',True),('virtual_slot',16),('fifth_argument_bits',1)):
            c=seed();target=c if key.endswith('_bytes') else c['sender'];target[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):rules.roots(c)

    def test_aliases_and_extra_native_admission_are_rejected(self):
        for mode in ('budget','root','leaf','numeric_duplicate','fixture'):
            c=seed()
            if mode=='budget':c['function_budget']=32
            if mode=='root':c['functions']['sender']=c['functions']['prepare']
            if mode=='leaf':c['leaves'][c['functions']['sender']]='c3'
            if mode=='numeric_duplicate':
                at=next(iter(c['leaves']));raw=c['leaves'].pop(at);other=next(iter(c['leaves']));c['leaves']['0x0'+other[2:]]=raw
            if mode=='fixture':c['sender']['pending_insert']=c['functions']['prepare']
            with self.subTest(mode=mode),self.assertRaises(ValueError):rules.roots(c)

    def test_native_getter_must_read_the_declared_singleton(self):
        for mode in ('global','body','extent'):
            c=seed();at=c['sender']['service_getter']
            if mode=='global':c['sender']['service_global']=hex(int(c['sender']['service_global'],16)+8)
            if mode=='body':c['leaves'][at]='488b0148ff6010c3'
            if mode=='extent':c['leaves'][at]='c3'
            with self.subTest(mode=mode),self.assertRaisesRegex(ValueError,'getter'):rules.roots(c)

    def test_parent_role_pointers_and_object_types_fail_closed(self):
        for key in ('prepare_context','wire_context'):
            c=seed();c[key]['sha256']='short'
            with self.subTest(key=key),self.assertRaises(ValueError):rules.roots(c)
        for key in ('functions','sender','source_inputs','leaves'):
            c=seed();c[key]=None
            with self.subTest(key=key),self.assertRaises(ValueError):rules.roots(c)

    def test_virtual_singleton_requires_eight_zero_fill_bytes(self):
        section=dict(name='.data',rva=100,raw=80,raw_size=20,size=100)
        def offset(_):raise ValueError('virtual tail')
        image=SimpleNamespace(pe=SimpleNamespace(base=1000,sections=[section]),offset=offset)
        self.assertEqual(rules.virtual_input(image,1192),dict(address=hex(1192),size_bytes=8,span=section))
        for at in (1119,1193):
            with self.subTest(at=at),self.assertRaises(ValueError):rules.virtual_input(image,at)
        image.offset=lambda _:0
        with self.assertRaisesRegex(ValueError,'file-backed'):rules.virtual_input(image,1140)


if __name__=='__main__':unittest.main()
