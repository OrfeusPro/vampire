"""Bounded PanelSlot/UniformGridSlot reads preserve omissions and reject unexplained bytes."""
import importlib.util
from pathlib import Path
import unittest

HERE=Path(__file__).parent/'resource-tools/vampir'
spec=importlib.util.spec_from_file_location('basic_slots',HERE/'decode-basic-slot-candidates.py')
slots=importlib.util.module_from_spec(spec);spec.loader.exec_module(slots)
PANEL=bytes.fromhex('0005bf0000001100000000000000')
UNIFORM=bytes.fromhex('8004020503480000005a00000000000000')
SCROLL=bytes.fromhex('0102020502030000a041170000001400000000000000')


class BasicSlotTests(unittest.TestCase):
    def test_panel_links_have_no_invented_geometry(self):
        v=slots.decode(PANEL,'PanelSlot')
        self.assertEqual(v['explicit_properties'],dict(Parent=191,Content=17))
        self.assertEqual(v['omitted_properties'],[])
        self.assertNotIn('padding',v)

    def test_uniform_zero_alignments_do_not_create_row_column_defaults(self):
        v=slots.decode(UNIFORM,'UniformGridSlot')
        self.assertEqual(v['explicit_properties'],dict(HorizontalAlignment=0,VerticalAlignment=0,Parent=72,Content=90))
        self.assertEqual(v['omitted_properties'],['Row','Column'])

    def test_opaque_suffix_truncation_and_null_links_fail(self):
        for raw in [PANEL[:-1],PANEL+b'\0',PANEL[:-1]+b'\1',PANEL[:2]+b'\0'*4+PANEL[6:]]:
            with self.subTest(raw=raw.hex()),self.assertRaises(ValueError):slots.decode(raw,'PanelSlot')

    def test_wrong_class_or_property_schema_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'Unsupported'):
            slots.decode(PANEL,'NamedSlot')
        with self.assertRaises(ValueError):slots.decode(UNIFORM,'PanelSlot')

    def test_scroll_preserves_nested_margin_and_outer_omissions(self):
        v=slots.decode(SCROLL,'ScrollBoxSlot')
        self.assertEqual(v['explicit_properties']['Parent'],23)
        self.assertEqual(v['explicit_properties']['Content'],20)
        padding=v['explicit_properties']['Padding']
        self.assertEqual(padding['explicit_properties'],dict(Right=20.0))
        self.assertEqual(padding['omitted_properties'],['Left','Top','Bottom'])
        self.assertEqual(v['omitted_properties'],['Size','HorizontalAlignment','VerticalAlignment'])

    def test_scroll_does_not_guess_explicit_size_or_accept_nonfinite_margin(self):
        with self.assertRaisesRegex(ValueError,'Size struct schema unreviewed'):
            slots.decode(b'\0'+SCROLL[1:],'ScrollBoxSlot')
        damaged=bytearray(SCROLL);damaged[6:10]=bytes.fromhex('0000c07f')
        with self.assertRaisesRegex(ValueError,'Invalid nested float'):
            slots.decode(bytes(damaged),'ScrollBoxSlot')

    def test_verified_size_schema_preserves_absent_weight(self):
        raw=bytes.fromhex('00020305010301180100000f01000000000000')
        with self.assertRaisesRegex(ValueError,'Size struct schema unreviewed'):
            slots.decode(raw,'ScrollBoxSlot')
        value=slots.decode(raw,'ScrollBoxSlot',allow_size=True)
        size=value['explicit_properties']['Size']
        self.assertEqual(size['explicit_properties'],dict(SizeRule=1))
        self.assertEqual(size['omitted_properties'],['Value'])
        self.assertNotIn('Value',size['explicit_properties'])
        self.assertEqual(value['explicit_properties']['Parent'],280)
        self.assertEqual(value['explicit_properties']['Content'],271)

    def test_verified_size_reads_explicit_float_and_rule_without_defaults(self):
        raw=bytes.fromhex('0002030500050000204001180100000f01000000000000')
        size=slots.decode(raw,'ScrollBoxSlot',allow_size=True)['explicit_properties']['Size']
        self.assertEqual(size['explicit_properties'],dict(Value=2.5,SizeRule=1))
        self.assertEqual(size['omitted_properties'],[])


if __name__=='__main__':unittest.main()
