import importlib.util,struct,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('point_links',Path(__file__).parent/'resource-tools/vampir/decode-navigation-point-links.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class NavigationPointLinkTests(unittest.TestCase):
    def decode(self,raw):return module.decode(module.canvas.Reader(raw))
    def test_explicit_points_and_direction_are_not_traversable_world_edge(self):
        raw=struct.pack('<HHddddddB',0x400,0x315,1.,2.,3.,4.,5.,6.,2)
        row=self.decode(raw)
        self.assertEqual(row['properties']['Left'],[1.,2.,3.])
        self.assertEqual(row['properties']['Right'],[4.,5.,6.])
        self.assertEqual(row['properties']['Direction'],2)
        self.assertFalse(row['world_coordinates_verified'])
        self.assertFalse(row['walkable_edge_verified'])
        self.assertNotIn('AreaClass',row['properties'])
    def test_explicit_zero_direction_is_kept_but_missing_array_is_distinct(self):
        row=self.decode(struct.pack('<HB',0x397,1))
        self.assertEqual(row['properties']['Direction'],0)
        reader=module.canvas.Reader(b'')
        self.assertEqual(module.array(reader,True),[])
        with self.assertRaises(ValueError):module.array(reader)
    def test_supported_agent_storage_is_not_a_permission_decision(self):
        row=self.decode(struct.pack('<HI',0x306,0x7fffffff))
        self.assertEqual(row['properties']['SupportedAgents']['raw_u32'],0x7fffffff)
        self.assertFalse(row['properties']['SupportedAgents']['interpretation_verified'])
    def test_bad_count_bool_vector_unknown_field_and_truncation_fail(self):
        for raw in [struct.pack('<i',-1),struct.pack('<i',10001)]:
            with self.assertRaises(ValueError):module.array(module.canvas.Reader(raw))
        for raw in [struct.pack('<HB',0x307,2),struct.pack('<Hddd',0x300,float('nan'),1.,2.),struct.pack('<H',0x323),b'\x00']:
            with self.assertRaises(ValueError):self.decode(raw)
if __name__=='__main__':unittest.main()
