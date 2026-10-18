import importlib.util,struct,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('lift_placement',Path(__file__).parent/'resource-tools/vampir/decode-lift-placements.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class LiftPlacementTests(unittest.TestCase):
    def test_explicit_location_does_not_create_rotation_scale_or_world_transform(self):
        raw=struct.pack('<Hddd',0x305,10.,20.,30.)+b'\0'*8
        row=module.decode(raw)
        self.assertEqual(row['properties'],{'RelativeLocation':[10.,20.,30.]})
        self.assertTrue(row['observed_zero_suffix_only'])
        self.assertFalse(row['world_transform_verified'])
        self.assertFalse(row['suffix_semantics_verified'])
    def test_zero_mask_is_explicit_zero_scale_not_default_unit_scale(self):
        row=module.decode(struct.pack('<HB',0x387,1)+b'\0'*8)
        self.assertEqual(row['properties']['RelativeScale3D'],[0.,0.,0.])
        self.assertNotIn('RelativeLocation',row['properties'])
    def test_absolute_location_bool_and_unknown_bytes_are_preserved(self):
        row=module.decode(struct.pack('<HB',0x30a,1)+b'\0'*8)
        self.assertTrue(row['properties']['bAbsoluteLocation'])
        row=module.decode(struct.pack('<H',0x30b)+b'unknown')
        self.assertEqual(row['unknown_fields'],[11])
        self.assertEqual(row['unresolved_suffix_hex'],b'unknown'.hex())
    def test_invalid_bool_nonfinite_or_truncated_transform_fails(self):
        for raw in [struct.pack('<HB',0x30a,2),struct.pack('<Hddd',0x305,float('inf'),1.,2.),struct.pack('<Hd',0x305,1.)]:
            with self.assertRaises(ValueError):module.decode(raw)
if __name__=='__main__':unittest.main()
