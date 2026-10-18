import importlib.util,math,struct,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('recast_geometry',Path(__file__).parent/'resource-tools/vampir/decode-recast-geometry.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class RecastGeometryTests(unittest.TestCase):
    def fixture(self):
        raw=bytearray(88);struct.pack_into('<H',raw,0,7);struct.pack_into('<HH',raw,4,2,4)
        raw+=struct.pack('<12d',0,0,0,1,0,0,0,0,1,1,0,1)
        for vertices,neighbors in [([0,1,2],[0x8002,2,0]),([2,1,3],[1,0,0])]:
            raw+=struct.pack('<I6H6HHBB',123,*vertices,0,0,0,*neighbors,0,0,0,1,3,10)
        return raw

    def test_internal_neighbors_use_one_based_ids_and_reversed_shared_edges(self):
        result=module.decode_tile(self.fixture())
        self.assertEqual(result['internal_links'],[[0,1,1],[1,0,0]])
        self.assertEqual(result['reciprocal_shared_edge_mismatches'],[])
        self.assertEqual(result['vertices'][3],[1.,0.,1.])
        self.assertEqual(result['high_bit_edges_unresolved'],[[0,0,0x8002]])
        self.assertEqual(result['polygons'][0]['first_link_serialized_raw'],123)

    def test_inactive_slots_are_not_vertex_or_neighbor_links(self):
        raw=self.fixture();struct.pack_into('<H',raw,88+96+4+6,65535)
        struct.pack_into('<H',raw,88+96+16+6,32767)
        self.assertEqual(module.decode_tile(raw)['reciprocal_shared_edge_mismatches'],[])

    def test_invalid_active_indices_counts_and_truncated_arrays_fail(self):
        raw=self.fixture();offset=88+96
        cases=[]
        for position,fmt,value in [(offset+4,'<H',4),(offset+16,'<H',3),(offset+30,'<B',0),(offset+30,'<B',7)]:
            changed=bytearray(raw);struct.pack_into(fmt,changed,position,value);cases.append(changed)
        cases+=[raw[:87],raw[:-1]]
        for changed in cases:
            with self.assertRaises(ValueError):module.decode_tile(changed)

    def test_nonfinite_coordinates_fail(self):
        for value in [math.nan,math.inf,-math.inf]:
            raw=self.fixture();struct.pack_into('<d',raw,88,value)
            with self.assertRaises(ValueError):module.decode_tile(raw)

    def test_nonreciprocal_or_geometrically_wrong_links_are_reported(self):
        raw=self.fixture();offset=88+96+32
        struct.pack_into('<H',raw,offset+4,3)
        self.assertEqual(len(module.decode_tile(raw)['reciprocal_shared_edge_mismatches']),2)

    def test_special_polygon_words_do_not_become_surface_links(self):
        raw=self.fixture();raw[88+96+31]=127
        result=module.decode_tile(raw)
        self.assertEqual(result['internal_links'],[[1,0,0]])
        self.assertEqual(result['high_bit_edges_unresolved'],[])
        self.assertEqual(result['polygons'][0]['area_type_raw'],127)


if __name__=='__main__':unittest.main()
