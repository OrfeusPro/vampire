import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'resource-tools/vampir'))
import ui_named_slot as named


class NamedSlotValueTests(unittest.TestCase):
    def schema(self):
        fields = [dict(name='Slots', reader='object_array'), dict(name='Slot', reader='object')]
        fields += [dict(name='Unknown' + str(i), reader='unreviewed') for i in range(2, 11)]
        fields.append(dict(name='bIsVariable', reader='bool'))
        return fields

    def test_explicit_fields_and_omissions_stay_separate(self):
        value = named.decode(bytes.fromhex('01020903060000000000000000'), self.schema())
        self.assertEqual(value['candidate_explicit_properties'], dict(Slot=6, bIsVariable=False))
        self.assertIn('Slots', value['omitted_properties'])
        self.assertFalse(value['defaults_applied'])
        self.assertFalse(value['geometry_verified'])

    def test_empty_record_does_not_invent_defaults(self):
        value = named.decode(bytes.fromhex('180100000000'), self.schema())
        self.assertEqual(value['candidate_explicit_properties'], {})
        self.assertEqual(len(value['omitted_properties']), 12)

    def test_array_then_own_slot_remains_two_fields(self):
        value = named.decode(bytes.fromhex('0005010000002d0000003800000000000000'), self.schema())
        self.assertEqual(value['candidate_explicit_properties'], dict(Slots=[45], Slot=56))

    def test_serialized_zero_is_not_an_omission(self):
        for header, key, expected in [(0x380, 'Slots', []), (0x381, 'Slot', 0), (0x38b, 'bIsVariable', False)]:
            value = named.decode(struct.pack('<HB I', header, 1, 0), self.schema())
            self.assertEqual(value['candidate_explicit_properties'], {key: expected})
            self.assertEqual(value['serialized_zero_fields'], [key])
            self.assertNotIn(key, value['omitted_properties'])

    def test_truncation_extra_bytes_unknown_reader_and_bad_values_rejected(self):
        raw = bytes.fromhex('01030600000000000000')
        for malformed in [raw[:-1], raw + b'\0', bytes.fromhex('0103ffffffff00000000'),
                          bytes.fromhex('010b0000000000'), bytes.fromhex('0b030200000000')]:
            with self.assertRaises(ValueError): named.decode(malformed, self.schema())
        duplicate = bytes.fromhex('000302000000060000000600000000000000')
        with self.assertRaises(ValueError): named.decode(duplicate, self.schema())
        oversized = struct.pack('<HiI', 0x300, 2000, 0)
        with self.assertRaises(ValueError): named.decode(oversized, self.schema())


class NamedSlotChildTests(unittest.TestCase):
    def fixture(self):
        raw = bytes.fromhex('0005290000002e00000000000000')
        slot = dict(index=45, type='PanelSlot', outer=41, size=len(raw), sha256=named.hashlib.sha256(raw).hexdigest())
        owner = dict(index=41, outer=50, type='NamedSlot')
        child = dict(index=46, outer=50, type='CanvasPanel')
        return raw, slot, owner, {46: child}, dict(explicit_properties=dict(Parent=41, Content=46))

    def test_local_reciprocal_relation_preserves_unknown_geometry(self):
        result = named.panel_child_relation(*self.fixture())
        self.assertEqual((result['parent_export'], result['content_export']), (41, 46))
        self.assertFalse(result['geometry_verified'])
        self.assertFalse(result['defaults_applied'])

    def test_payload_owner_content_and_missing_links_rejected(self):
        for fault in ('hash', 'size', 'outer', 'parent', 'missing', 'outside', 'metadata', 'self'):
            raw, slot, owner, exports, decoded = self.fixture()
            if fault == 'hash': raw = raw[:-1] + b'\1'
            if fault == 'size': slot['size'] += 1
            if fault == 'outer': slot['outer'] = 42
            if fault == 'parent': decoded['explicit_properties']['Parent'] = 42
            if fault == 'missing': exports.clear()
            if fault == 'outside': exports[46]['outer'] = 51
            if fault == 'metadata': exports[46]['type'] = 'WidgetTree'
            if fault == 'self': decoded['explicit_properties']['Content'] = 41; exports[41] = owner
            with self.assertRaises(ValueError):
                named.panel_child_relation(raw, slot, owner, exports, decoded)


if __name__ == '__main__':
    unittest.main()
