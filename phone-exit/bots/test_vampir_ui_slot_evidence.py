"""Reusing a candidate parse is source-bound and cannot close geometry/default checks."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'
spec = importlib.util.spec_from_file_location('slot_evidence', HERE / 'reconcile-ui-slot-evidence.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)
RAW = bytes.fromhex('0302010203050700000004000000b30000003e00000000000000')


def fixture():
    candidate = dict(index=207,name='GridSlot_1',type='GridSlot',sha256=evidence.sha(RAW),offset=100,size=len(RAW))
    exports = {207: dict(candidate,serialized_hex=RAW.hex()),
        179: dict(index=179,name='GridPanel',type='GridPanel',sha256='a'*64),
        62: dict(index=62,name='Arena',type='CanvasPanel',sha256='b'*64)}
    variant = dict(source=dict(asset_sha256='c'*64,body_sha256='d'*64))
    source = dict(file='sample.json',slot_export=207,offset=100,size=len(RAW),sha256=evidence.sha(RAW),**variant['source'])
    proof = dict(source=source,decoded=evidence.grid.decode(RAW),parent=exports[179],content=exports[62])
    return candidate, variant, exports, proof


class SlotEvidenceTests(unittest.TestCase):
    def test_reproduction_preserves_omissions_and_does_not_promote_geometry(self):
        c,v,x,p=fixture()
        value=evidence.reproduce(c,v,'sample.json',x,p)
        self.assertTrue(value['automatic_check_passed'])
        self.assertFalse(value['geometry_verified'])
        self.assertFalse(value['implementation_verified'])
        self.assertIn('RowSpan',value['decoded']['omitted_properties'])
        self.assertNotIn('RowSpan',value['decoded']['explicit_properties'])

    def test_same_export_number_from_another_package_is_not_reused(self):
        c,v,x,p=fixture();v['source']['body_sha256']='f'*64
        with self.assertRaisesRegex(ValueError,'different package/export'):
            evidence.reproduce(c,v,'sample.json',x,p)

    def test_changed_interpretation_or_parent_is_rejected(self):
        c,v,x,p=fixture();p['decoded']['explicit_properties']['RowSpan']=1
        with self.assertRaisesRegex(ValueError,'explicit values differ'):
            evidence.reproduce(c,v,'sample.json',x,p)
        c,v,x,p=fixture();x[179]['type']='Overlay'
        with self.assertRaisesRegex(ValueError,'not GridPanel'):
            evidence.reproduce(c,v,'sample.json',x,p)

    def test_other_slot_type_cannot_use_grid_rule(self):
        c,v,x,p=fixture();x[207]['type']='PanelSlot'
        with self.assertRaisesRegex(ValueError,'another export type'):
            evidence.reproduce(c,v,'sample.json',x,p)

    def test_panel_provider_reuses_only_explicit_links(self):
        raw=bytes.fromhex('0005bf0000001100000000000000')
        c=dict(index=248,name='PanelSlot_0',type='PanelSlot',sha256=evidence.sha(raw),offset=100,size=len(raw))
        x={248:dict(c,serialized_hex=raw.hex()),191:dict(index=191,name='Check',type='NkCheckBox',sha256='a'*64),
            17:dict(index=17,name='Canvas',type='CanvasPanel',sha256='b'*64)}
        v=dict(source=dict(asset_sha256='c'*64,body_sha256='d'*64))
        p=dict(kind='PanelSlot',source=dict(file='sample.json',slot_export=248,offset=100,size=len(raw),sha256=evidence.sha(raw),**v['source']),
            decoded=evidence.basic.decode(raw,'PanelSlot'),parent=x[191],content=x[17])
        result=evidence.reproduce(c,v,'sample.json',x,p)
        self.assertTrue(result['automatic_check_passed'])
        self.assertFalse(result['geometry_verified'])
        self.assertEqual(result['decoded']['explicit_properties'],dict(Parent=191,Content=17))

    def test_uniform_provider_preserves_missing_coordinates(self):
        raw=bytes.fromhex('8004020503480000005a00000000000000')
        c=dict(index=73,name='Uniform',type='UniformGridSlot',sha256=evidence.sha(raw),offset=100,size=len(raw))
        x={73:dict(c,serialized_hex=raw.hex()),72:dict(index=72,name='Grid',type='UniformGridPanel',sha256='a'*64),
            90:dict(index=90,name='Entry',type='Entry_C',sha256='b'*64)}
        v=dict(source=dict(asset_sha256='c'*64,body_sha256='d'*64))
        p=dict(kind='UniformGridSlot',source=dict(file='sample.json',slot_export=73,offset=100,size=len(raw),sha256=evidence.sha(raw),**v['source']),
            decoded=evidence.basic.decode(raw,'UniformGridSlot'),parent=x[72],content=x[90])
        result=evidence.reproduce(c,v,'sample.json',x,p)
        self.assertEqual(result['decoded']['omitted_properties'],['Row','Column'])
        x[72]['type']='Overlay'
        with self.assertRaisesRegex(ValueError,'not UniformGridPanel'):
            evidence.reproduce(c,v,'sample.json',x,p)

    def test_named_container_classification_keeps_inherited_payload_opaque(self):
        raw=bytes.fromhex('01032600000000000000')
        c=dict(index=34,name='Named',type='NamedSlot',sha256=evidence.sha(raw),offset=100,size=len(raw))
        x={34:dict(c,outer=44,serialized_hex=raw.hex()),44:dict(index=44,name='Tree',type='WidgetTree',sha256='a'*64)}
        v=dict(source=dict(asset_sha256='c'*64,body_sha256='d'*64))
        p=dict(kind='NamedSlot',source=dict(file='sample.json',slot_export=34,offset=100,size=len(raw),sha256=evidence.sha(raw),**v['source']),
            decoded=None,raw_serialization_hex=raw.hex(),outer=x[44])
        result=evidence.reproduce(c,v,'sample.json',x,p)
        self.assertTrue(result['automatic_check_passed'])
        self.assertEqual(result['status'],'container_candidate_classified')
        self.assertFalse(result['candidate_parse_complete'])
        self.assertFalse(result['inherited_properties_decoded'])
        self.assertFalse(result['geometry_verified'])
        p['raw_serialization_hex']='00'
        with self.assertRaisesRegex(ValueError,'opaque payload differs'):
            evidence.reproduce(c,v,'sample.json',x,p)

    def test_scroll_provider_requires_scrollbox_parent(self):
        raw=bytes.fromhex('0102020502030000a041170000001400000000000000')
        c=dict(index=24,name='Scroll',type='ScrollBoxSlot',sha256=evidence.sha(raw),offset=100,size=len(raw))
        x={24:dict(c,serialized_hex=raw.hex()),23:dict(index=23,name='Scroll',type='ScrollBox',sha256='a'*64),
            20:dict(index=20,name='Text',type='TextBlock',sha256='b'*64)}
        v=dict(source=dict(asset_sha256='c'*64,body_sha256='d'*64))
        p=dict(kind='ScrollBoxSlot',source=dict(file='sample.json',slot_export=24,offset=100,size=len(raw),sha256=evidence.sha(raw),**v['source']),
            decoded=evidence.basic.decode(raw,'ScrollBoxSlot'),parent=x[23],content=x[20])
        result=evidence.reproduce(c,v,'sample.json',x,p)
        self.assertTrue(result['candidate_parse_complete'])
        x[23]['type']='Overlay'
        with self.assertRaisesRegex(ValueError,'not ScrollBox'):
            evidence.reproduce(c,v,'sample.json',x,p)

    def test_explicit_size_needs_verified_provider_and_does_not_supply_weight(self):
        raw=bytes.fromhex('00020305010301180100000f01000000000000')
        c=dict(index=281,name='Scroll',type='ScrollBoxSlot',sha256=evidence.sha(raw),offset=100,size=len(raw))
        x={281:dict(c,serialized_hex=raw.hex()),280:dict(index=280,name='Scroll',type='ScrollBox',sha256='a'*64),
            271:dict(index=271,name='Content',type='TextBlock',sha256='b'*64)}
        v=dict(source=dict(asset_sha256='c'*64,body_sha256='d'*64))
        p=dict(kind='ScrollBoxSlot',source=dict(file='sample.json',slot_export=281,offset=100,size=len(raw),sha256=evidence.sha(raw),**v['source']),
            decoded=evidence.basic.decode(raw,'ScrollBoxSlot',allow_size=True),parent=x[280],content=x[271])
        with self.assertRaisesRegex(ValueError,'Size struct schema unreviewed'):
            evidence.reproduce(c,v,'sample.json',x,p)
        p['allow_explicit_size']=True
        result=evidence.reproduce(c,v,'sample.json',x,p)
        size=result['decoded']['explicit_properties']['Size']
        self.assertNotIn('Value',size['explicit_properties'])
        self.assertEqual(size['omitted_properties'],['Value'])
        self.assertFalse(result['geometry_verified'])

    def test_incomplete_or_duplicate_evidence_is_rejected(self):
        _,_,_,p=fixture()
        report=dict(kind='grid_slot_candidate_decode',failures=[],
            native_source=dict(sha256=evidence.grid.SOURCE_SHA),
            class_links=dict(source_sha256=evidence.grid.SOURCE_SHA),tools={},records=[p,p])
        with self.assertRaisesRegex(ValueError,'Incomplete evidence tool'):
            evidence.evidence_index(report)
        report['tools']={n:evidence.sha((HERE/n).read_bytes()) for n in
            ['decode-grid-slots.py','extract-ui-properties.py','decode-canvas-slots.py','inspect-ui.py']}
        with self.assertRaisesRegex(ValueError,'Duplicate'):
            evidence.evidence_index(report)
        report['records']=[copy.deepcopy(p)];report['tools']['inspect-ui.py']='0'*64
        with self.assertRaisesRegex(ValueError,'tool changed'):
            evidence.evidence_index(report)


if __name__ == '__main__':
    unittest.main()
