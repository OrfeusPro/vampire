"""Typed action tails, constrained registration candidates and mutable extents."""
import struct
from types import SimpleNamespace
import unittest

from test_vampir_update_contracts import load

RULES = load('quest-action-transfer-rules-v1')
NATIVE = load('build-native-entry-code')


def image(raw, base):
    return SimpleNamespace(data=bytes(raw), offset=lambda rva: rva,
        pe=SimpleNamespace(base=base, sections=[dict(name='.text',rva=0,raw=0,raw_size=len(raw),size=len(raw))]))


def rows(raw, base):
    return RULES.decode(NATIVE,image(raw,base),base,len(raw))


def jump(source, target):
    return b'\xe9'+struct.pack('<i',target-source-5)


class ActionRuleGuardTests(unittest.TestCase):
    def test_declared_direct_tail_preserves_the_linked_callee(self):
        before=rows(jump(0x1000,0x1800),0x1000);after=rows(jump(0x2000,0x2a00),0x2000)
        mapping={0x1800:0x2a00}
        RULES.pair(NATIVE,before,after,mapping,RULES.row_policy(before,0x1000))
        self.assertEqual(mapping,{0x1800:0x2a00,0x1000:0x2000})

    def test_external_tail_requires_the_exact_declared_offset(self):
        before=rows(jump(0x1000,0x1800),0x1000);after=rows(jump(0x2000,0x2a00),0x2000)
        spec=RULES.row_policy(before,0x1000);spec['tails']={'1':'0x1800'}
        with self.assertRaisesRegex(ValueError,'policy'):
            RULES.pair(NATIVE,before,after,{},spec)

    def test_conditional_external_branch_does_not_become_an_approved_tail(self):
        before=rows(b'\x0f\x85'+struct.pack('<i',0x1800-0x1006),0x1000)
        after=rows(b'\x0f\x85'+struct.pack('<i',0x2a00-0x2006),0x2000)
        with self.assertRaisesRegex(ValueError,'outside typed tail'):
            RULES.pair(NATIVE,before,after,{},RULES.row_policy(before,0x1000))

    def test_indirect_external_jump_cannot_be_registered_as_a_direct_tail(self):
        before=rows(b'\xff\x60\x20',0x1000);after=rows(b'\xff\x60\x20',0x2000)
        with self.assertRaisesRegex(ValueError,'outside typed tail'):
            RULES.pair(NATIVE,before,after,{},RULES.row_policy(before,0x1000))

    def test_same_shape_candidate_with_a_different_known_callee_is_rejected(self):
        before=rows(jump(0x1000,0x1800),0x1000);after=rows(jump(0x2000,0x2a00),0x2000)
        with self.assertRaisesRegex(ValueError,'inconsistent'):
            RULES.pair(NATIVE,before,after,{0x1800:0x2b00},RULES.row_policy(before,0x1000))

    def test_registration_uses_linked_pointer_and_constructor_before_candidate_budget(self):
        source=0x100000;old_table=0x130000;old_ctor=0x140000
        def window(at,table,ctor):
            return b'\x48\x8d\x05'+struct.pack('<i',table-at-7)+b'\xe8'+struct.pack('<i',ctor-at-12)+b'\xc3'
        old=window(source,old_table,old_ctor);before=rows(old,source)
        base=0x100100;data=bytearray(b'\xcc'*4096);chosen=base+63*32
        for number in range(64):
            at=base+number*32;payload=window(at,0x230000 if at==chosen else 0x240000,0x250000)
            data[number*32:number*32+len(payload)]=payload
        spec=RULES.row_policy(before,source);mapping={old_table:0x230000,old_ctor:0x250000}
        def matches(at):
            try:RULES.pair(NATIVE,before,RULES.decode(NATIVE,image(data,base),at,len(old)),dict(mapping),spec)
            except ValueError:return False
            return True
        mask=list(range(3,7))+list(range(8,12))
        self.assertEqual(RULES.masked_hits(image(data,base),source,old,mask,matches),[chosen])

    def test_registration_without_a_unique_link_remains_a_concrete_blocker(self):
        raw=b'\x48\x8d\x05'+b'\0'*4+b'\xc3'
        data=raw*40
        with self.assertRaisesRegex(ValueError,'candidate budget'):
            RULES.masked_hits(image(data,0x100000),0x100000,raw,list(range(3,7)))

    def test_mutable_pointer_checks_extent_without_reading_or_freezing_value(self):
        slot=SimpleNamespace(pe=SimpleNamespace(base=0x1000,
            sections=[dict(name='.data',rva=0x100,size=8)]))
        self.assertEqual(RULES.mutable_storage(slot,0x1100),'.data')
        for at in (0x10ff,0x1101):
            with self.assertRaisesRegex(ValueError,'bounded data storage'):
                RULES.mutable_storage(slot,at)
        with self.assertRaisesRegex(ValueError,'exactly eight'):
            RULES.mutable_storage(slot,0x1100,16)

    def test_mutable_pointer_cannot_alias_readonly_or_ambiguous_storage(self):
        slot=SimpleNamespace(pe=SimpleNamespace(base=0x1000,
            sections=[dict(name='.rdata',rva=0x100,size=8)]))
        with self.assertRaisesRegex(ValueError,'bounded data storage'):RULES.mutable_storage(slot,0x1100)
        slot.pe.sections=[dict(name='.data',rva=0x100,size=8)]*2
        with self.assertRaisesRegex(ValueError,'bounded data storage'):RULES.mutable_storage(slot,0x1100)


if __name__=='__main__':unittest.main()
