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
