"""Proof inventory and source-tail boundaries cannot be widened by a recipe."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from test_vampir_update_contracts import load

HERE=Path(__file__).resolve().parent/'resource-tools/vampir'


def seed():return json.loads((HERE/'knowledge/native-contexts/login-backend-wire-11322.json').read_text('utf-8'))


class BackendWireRulesTests(unittest.TestCase):
    def setUp(self):self.rules=load('login-backend-wire-rules')

    def test_exact_inventory_separates_tails_and_excludes_version_writer(self):
        c=seed();self.assertEqual(len(self.rules.roots(c)),29)
        self.assertEqual((len(c['leaves']),len(c['tails'])),(13,3))
        self.assertNotIn('0x1456e4500',c['functions'].values())
        self.assertEqual(c['format'],self.rules.REFERENCE)
        self.assertNotIn('transfer_proof',c)
        self.assertEqual(c['source_inputs']['archive_flags']['bytes'],'01000000')

    def test_extent_slot_integer_and_added_budget_fail_closed(self):
        for field,value in (('backend_bytes',769),('archive_bytes',True),('service_bytes',248),('function_budget',64)):
            c=seed();c[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.rules.roots(c)
        for field,value in (('virtual_slot',16),('fifth_argument_bits',True)):
            c=seed();c['sender'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.rules.roots(c)

    def test_returning_tail_and_native_fixture_aliases_are_rejected(self):
        for mode in ('tail-as-leaf','extra-root','fixture-entry','id-value','duplicate-address','missing-parent-sha'):
            c=seed()
            if mode=='tail-as-leaf':
                at,raw=c['tails'].popitem();c['leaves'][at]=raw
            if mode=='extra-root':c['functions']['unreviewed']='0x144ab13f0'
            if mode=='fixture-entry':c['backend']['transport']=c['functions']['publisher']
            if mode=='id-value':c['leaves'][c['backend']['packet_id_getter']]='b804000000c3'
            if mode=='duplicate-address':c['functions']['wire.append']=c['functions']['backend']
            if mode=='missing-parent-sha':c['handoff_context']['sha256']='short'
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.rules.roots(c)

    def row(self,**kw):
        return dict(address=0x100,bytes='e900000000',branch=True,call=False,direct_target=0x200,
            mnemonic='jmp',operands='0x200',rip_references=[],**kw)

    def paired(self,before,**kw):
        after=copy.deepcopy(before)
        for r in after:r['address']+=0x1000
        source=SimpleNamespace(signature=lambda n,r:'shape')
        real=self.rules.load
        with patch.object(self.rules,'load',side_effect=lambda n:source if n=='update-native-contexts' else real(n)):
            self.rules.pair_rows(None,before,after,{},**kw)

    def test_only_reviewed_cleanup_target_can_cross_native_unwind_boundary(self):
        self.paired([self.row()],declared_tails={0x200})
        with self.assertRaisesRegex(ValueError,'unreviewed'):self.paired([self.row()])
        with self.assertRaisesRegex(ValueError,'unreviewed'):self.paired([self.row()],declared_tails={0x201})

    def test_virtual_tail_requires_terminal_jmp_rax_and_explicit_permission(self):
        row=self.row();row.update(bytes='48ffe0',direct_target=None,operands='rax')
        self.paired([row],virtual_tail=True)
        with self.assertRaisesRegex(ValueError,'unreviewed'):self.paired([row])
        bad=copy.deepcopy(row);bad['operands']='rcx'
        with self.assertRaisesRegex(ValueError,'unreviewed'):self.paired([bad],virtual_tail=True)
        ret=dict(address=0x110,bytes='c3',branch=False,call=False,direct_target=None,mnemonic='ret',operands='',rip_references=[])
        with self.assertRaisesRegex(ValueError,'unreviewed'):self.paired([row,ret],virtual_tail=True)

    def test_inconsistent_relocation_and_rip_edges_are_blockers(self):
        row=self.row();row.update(branch=False,call=True,mnemonic='call',rip_references=[0x700])
        after=copy.deepcopy(row);after['address']+=0x1000;after['rip_references']=[]
        source=SimpleNamespace(signature=lambda n,r:'shape');real=self.rules.load
        with patch.object(self.rules,'load',side_effect=lambda n:source if n=='update-native-contexts' else real(n)):
            with self.assertRaisesRegex(ValueError,'data edges'):self.rules.pair_rows(None,[row],[after],{})
        with self.assertRaisesRegex(ValueError,'inconsistent'):
            load('update-native-archive-wire').add_link({1:2},1,3)

    def test_global_provider_and_table_inventory_cannot_be_dropped(self):
        for mode in ('field','globals','service-width'):
            c=seed()
            if mode=='field':c['source_inputs'].pop('archive_flags')
            if mode=='globals':c['backend']['globals']['unknown']='0x100'
            if mode=='service-width':c['service']['object_bytes']=True
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.rules.roots(c)


if __name__=='__main__':unittest.main()
