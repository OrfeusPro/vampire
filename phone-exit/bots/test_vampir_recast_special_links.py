import importlib.util,math,struct,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('special_points',Path(__file__).parent/'resource-tools/vampir/decode-recast-special-links.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class SpecialPointTests(unittest.TestCase):
    def fixture(self,identifier=0):
        raw=bytearray(88)
        for off,value in [(0,7),(4,2),(6,5),(18,1),(22,1),(26,1),(28,1)]:struct.pack_into('<H',raw,off,value)
        raw+=struct.pack('<15d',0,0,0,1,0,0,0,0,1,0,5,0,10,20,0)
        for verts,count,kind in [([0,1,2,0,0,0],3,10),([3,4,0,0,0,0],2,127)]:raw+=struct.pack('<I6H6HHBB',0,*verts,*([0]*6),1,count,kind)
        raw+=struct.pack('<HHBB',0,0,0,1)+bytes(2)+bytes([0,1,2,0])+bytes(4)
        raw+=struct.pack('<8dQHBB4s',0,5.1,0,10,21,0,30,40,identifier,1,128,192,b'abcd')
        raw+=bytes(8)
        return raw

    def test_original_and_baked_endpoints_stay_distinct(self):
        points,unknown=module.decode_points(self.fixture());p=points[0]
        self.assertEqual(unknown,[]);self.assertFalse(p['attachment_verified'])
        self.assertEqual(p['original_world'][0],[0,0,5.1]);self.assertEqual(p['baked_vertex_world'][0],[0,0,5])
        self.assertAlmostEqual(p['baked_endpoint_shift'][0],.1)
        self.assertEqual(p['tail_uninterpreted_hex'],b'abcd'.hex())

    def test_identifiers_preserve_zero_and_uint64_without_float(self):
        for value in [0,2**64-1]:self.assertEqual(module.decode_points(self.fixture(value))[0][0]['identifier_raw'],str(value))

    def test_nonfinite_and_wrong_polygon_fail(self):
        for offset,fmt,value in [(288,'<d',math.nan),(288+72,'<H',0),(88+120+32+4,'<H',5)]:
            raw=self.fixture();struct.pack_into(fmt,raw,offset,value)
            with self.assertRaises(ValueError):module.decode_points(raw)

    def test_coordinate_coincidence_is_not_component_binding(self):
        world=[[0,0,0],[10,0,20]];lifts=[dict(id='1',calculated_links=[dict(index=0,left=world[0],right=world[1])])]
        matches=module.spatial_candidates(world,lifts)
        self.assertEqual(len(matches),1);self.assertFalse(matches[0]['component_binding_verified'])
        self.assertEqual(module.spatial_candidates(world[::-1],lifts),[])
        self.assertEqual(module.spatial_candidates([[0,0,1],[10,0,20]],lifts),[])


if __name__=='__main__':unittest.main()
