"""Source-constrained quest reader relocation rejects ambiguous or changed code."""
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from test_vampir_update_contracts import load

RULES=load('quest-reader-transfer-rules-v1')
NATIVE=load('build-native-entry-code')


def instruction(address,raw='c3',mnemonic='ret',operands='',target=None,rips=(),call=False,branch=False):
    return dict(address=address,bytes=raw,mnemonic=mnemonic,operands=operands,direct_target=target,
        rip_references=list(rips),call=call,branch=branch)


def read_bytes(image,address,size):
    for origin,raw in image.memory.items():
        if origin<=address and address+size<=origin+len(raw):
            return raw[address-origin:address-origin+size]
    raise ValueError('Synthetic read is outside declared memory')


class QuestReaderRuleTests(unittest.TestCase):
    def setUp(self):
        self.common=load('update-native-archive-wire')

    def test_reviewed_calls_require_the_exact_callee_and_offset(self):
        rows=[instruction(0x1000,'e800000000','call','0x5000',target=0x5000,call=True)]
        spec=dict(calls={'0':'0x5000'},data={})
        RULES.check_policy(rows,0x1000,spec)
        rows[0]['direct_target']=0x5001
        with self.assertRaisesRegex(ValueError,'call-site policy'):RULES.check_policy(rows,0x1000,spec)
        rows[0]['direct_target']=0x5000;rows[0]['address']=0x1001
        with self.assertRaisesRegex(ValueError,'call-site policy'):RULES.check_policy(rows,0x1000,spec)

    def test_undeclared_rip_data_is_a_blocker_even_without_new_calls(self):
        row=instruction(0x1000,'488d0500000000','lea','rax, [rip]',rips=(0x5000,))
        spec=dict(calls={},data={'0':['0x5000']})
        RULES.check_policy([row],0x1000,spec)
        row['rip_references'].append(0x5008)
        with self.assertRaisesRegex(ValueError,'undeclared RIP'):RULES.check_policy([row],0x1000,spec)

    def test_constructor_candidates_are_constrained_by_the_packet_table(self):
        before,after=object(),object();old,good,other=0x1000,0x2000,0x2100
        def rows(native,image,at):
            table=0x5000 if image is before else 0x9000 if at==good else 0x9100
            return [instruction(at,'488d0500000000','lea','rax, [rip]',rips=(table,)),instruction(at+7)]
        bindings=SimpleNamespace(rows=rows);api=SimpleNamespace(candidates=lambda *a:[other,good])
        mapping={0x5000:0x9000}
        report=RULES.resolve_roots(NATIVE,bindings,api,self.common,before,after,{old},mapping)
        self.assertEqual(report,[dict(baseline=hex(old),target=hex(good),candidates=2)])
        self.assertEqual(mapping[old],good);self.assertNotIn(other,mapping.values())

    def test_reserve_candidates_share_shape_but_only_one_calls_the_bound_fixture(self):
        before,after=object(),object();old=0x1000;candidates=[0x2000+i*0x100 for i in range(12)];good=candidates[-1]
        def rows(native,image,at):
            target=0x5000 if image is before else 0x9000 if at==good else 0xa000+at
            return [instruction(at,'e800000000','call',hex(target),target=target,call=True),instruction(at+5)]
        mapping={0x5000:0x9000};api=SimpleNamespace(candidates=lambda *a:candidates)
        reports=RULES.resolve_roots(NATIVE,SimpleNamespace(rows=rows),api,self.common,before,after,{old},mapping)
        self.assertEqual(reports[0]['candidates'],12);self.assertEqual(mapping[old],good)

    def test_unconstrained_identical_candidates_remain_ambiguous(self):
        before,after=object(),object()
        bindings=SimpleNamespace(rows=lambda native,image,at:[instruction(at)])
        api=SimpleNamespace(candidates=lambda *a:[0x2000,0x2100]);mapping={}
        with self.assertRaisesRegex(ValueError,'ambiguous call-constrained'):
            RULES.resolve_roots(NATIVE,bindings,api,self.common,before,after,{0x1000},mapping)
        self.assertEqual(mapping,{})

    def packets(self):
        base=0x140000000;raw=bytearray(b'\x90'*0x200);reviewed=dict(packets={});before=SimpleNamespace(memory={})
        after=SimpleNamespace(pe=SimpleNamespace(base=base,sections=[dict(name='.text',rva=0x1000,raw=0,raw_size=len(raw))]),
            offset=lambda rva:rva-0x1000,memory={})
        anchors={}
        for n,(name,packet_id) in enumerate((('quest-sync',1854),('tutorial-update',9905))):
            old=base+0x1000+n*0x100;new=old+0x10;table=base+0x5000+n*0x100;current_table=table+0x1000
            old_reader=base+0x8000+n*0x100;reader=old_reader+0x2000
            leaf=b'\xb8'+struct.pack('<I',packet_id)+b'\xc3';before.memory[old]=leaf
            raw[0x10+n*0x100:0x16+n*0x100]=leaf
            after.memory[current_table]=bytes(32)+struct.pack('<QQ',reader,new)
            reviewed['packets'][name]=dict(id_getter=hex(old),id=packet_id,table=hex(table),reader=hex(old_reader))
            anchors[table]=(new,current_table,old_reader,reader)
        after.data=bytes(raw)
        def tables(image,table,target,slot,size):
            expected,current,_,_=anchors[table]
            self.assertEqual((image,slot,size),(after,0x28,0x30))
            self.assertEqual(target,expected)
            return [current]
        return before,after,reviewed,anchors,SimpleNamespace(image_bytes=read_bytes,table_candidates=Mock(side_effect=tables))

    def test_packet_ids_bind_both_readers_through_their_own_virtual_tables(self):
        before,after,policy,anchors,api=self.packets();mapping={}
        RULES.anchor_packets(api,self.common,before,after,policy,mapping)
        self.assertEqual(api.table_candidates.call_count,2)
        for table,(_,current,old_reader,reader) in anchors.items():
            self.assertEqual(mapping[table],current);self.assertEqual(mapping[old_reader],reader)
            bindings=SimpleNamespace(rows=lambda native,image,at:[instruction(at)])
            candidates=SimpleNamespace(candidates=lambda *a:[reader+0x10,reader])
            RULES.resolve_roots(NATIVE,bindings,candidates,self.common,before,after,{old_reader},mapping)
            self.assertEqual(mapping[old_reader],reader)

    def test_packet_id_requires_the_exact_returned_value(self):
        before,after,policy,anchors,api=self.packets()
        getter=int(policy['packets']['quest-sync']['id_getter'],16)
        before.memory[getter]=b'\xb8'+struct.pack('<I',1855)+b'\xc3'
        with self.assertRaisesRegex(ValueError,'ID baseline differs'):
            RULES.anchor_packets(api,self.common,before,after,policy,{})
        api.table_candidates.assert_not_called()

    def test_multiple_id_linked_tables_are_not_resolved_by_order(self):
        before,after,policy,anchors,api=self.packets()
        api.table_candidates=Mock(return_value=[0x140006000,0x140006100])
        with self.assertRaisesRegex(ValueError,'ID-linked table missing or ambiguous'):
            RULES.anchor_packets(api,self.common,before,after,policy,{})

    def table(self):
        before=SimpleNamespace(memory={0x1000:struct.pack('<4Q',0x10,0x20,0x10,0x30)})
        after=SimpleNamespace(memory={0x2000:struct.pack('<4Q',0x110,0x120,0x110,0x130)})
        spec=dict(baseline='0x1000',bytes=before.memory[0x1000].hex(),used={'0x8':'0x20'},kind='descriptor')
        return before,after,spec,{0x1000:0x2000,0x20:0x120}

    def test_pointer_table_alias_partition_is_preserved_for_unselected_slots(self):
        before,after,spec,mapping=self.table();api=SimpleNamespace(image_bytes=read_bytes)
        report=RULES.check_table(api,before,after,spec,mapping)
        self.assertEqual(report['used'],{'0x8':'0x120'});self.assertFalse(report['unselected_bodies_verified'])
        after.memory[0x2000]=struct.pack('<4Q',0x110,0x120,0x130,0x130)
        with self.assertRaisesRegex(ValueError,'alias partition'):
            RULES.check_table(api,before,after,spec,{0x1000:0x2000,0x20:0x120})

    def test_used_table_role_requires_the_caller_constrained_target(self):
        before,after,spec,mapping=self.table();mapping[0x20]=0x121
        with self.assertRaisesRegex(ValueError,'used role differs'):
            RULES.check_table(SimpleNamespace(image_bytes=read_bytes),before,after,spec,mapping)

    def test_fixture_must_begin_at_its_unwind_entry(self):
        def image(origin):
            return SimpleNamespace(pe=SimpleNamespace(base=0),roots={origin:(origin,origin+32)},
                containing=lambda at:origin if origin<=at<origin+32 else None)
        before,after=image(0x1000),image(0x2000)
        report=RULES.check_boundary(NATIVE,None,before,after,0x1000,0x2000)
        self.assertFalse(report['body_verified'])
        for old,target in ((0x1001,0x2000),(0x1000,0x2001),(0x1000,0x3000)):
            with self.subTest(old=old,target=target),self.assertRaisesRegex(ValueError,'exact unwind entry'):
                RULES.check_boundary(NATIVE,None,before,after,old,target)


if __name__=='__main__':unittest.main()
