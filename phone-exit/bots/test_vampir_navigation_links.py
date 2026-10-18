import importlib.util,struct,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('nav_links',Path(__file__).parent/'resource-tools/vampir/decode-navigation-links.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class NavigationLinkTests(unittest.TestCase):
    def test_uint64_ids_and_relative_endpoints_preserved_without_defaults(self):
        raw=struct.pack('<HHHQdddddd',0x201,0x504,0x300,2**64-1,1.,2.,3.,4.,5.,6.)+b'\0'*8
        row=module.decode(raw)
        self.assertEqual(row['properties']['CustomLinkId'],str(2**64-1))
        self.assertEqual(row['properties']['LinkRelativeStart'],[1.,2.,3.])
        self.assertEqual(row['properties']['LinkRelativeEnd'],[4.,5.,6.])
        self.assertNotIn('AuxiliaryCustomLinkId',row['properties'])
        self.assertIsNone(row['direction'])
        self.assertIsNone(row['enabled'])
        self.assertFalse(row['walkable_edge_verified'])
        self.assertTrue(row['observed_zero_suffix_only'])
        self.assertFalse(row['suffix_semantics_verified'])
    def test_unknown_field_retains_tail_without_guessing_size(self):
        raw=struct.pack('<HHHQ',0x201,0x30c,0x300,123)+b'opaque'
        row=module.decode(raw)
        self.assertEqual(row['unknown_fields'],[14])
        self.assertEqual(row['unresolved_suffix_hex'],b'opaque'.hex())
        self.assertNotIn('LinkRelativeStart',row['properties'])
    def test_explicit_zero_differs_from_omitted_endpoint(self):
        row=module.decode(struct.pack('<HB',0x386,1)+b'\0'*8)
        self.assertEqual(row['properties']['LinkRelativeStart'],[0.,0.,0.])
        self.assertNotIn('LinkRelativeEnd',row['properties'])
    def test_truncated_or_nonfinite_vector_is_rejected(self):
        for raw in [struct.pack('<H',0x306)+b'\0',struct.pack('<Hddd',0x306,float('nan'),1.,2.)]:
            with self.assertRaises(ValueError):module.decode(raw)
if __name__=='__main__':unittest.main()
