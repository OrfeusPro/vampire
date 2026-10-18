import importlib.util,math,struct,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('nav_params',Path(__file__).parent/'resource-tools/vampir/decode-recast-nav-params.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class NavigationParameterTests(unittest.TestCase):
    def stream(self):
        return struct.pack('<i5d2i6d',0,0,0,0,1000,1000,100,1000,144,35,35,.025,.051,.051)

    def envelope(self):return struct.pack('<iI',26,104)+self.stream()

    def test_uint32_envelope_and_parameter_order(self):
        candidates=module.find_candidates(b'prefix'+self.envelope())
        self.assertEqual(len(candidates),1);candidate=candidates[0]
        self.assertEqual(candidate['offset'],6)
        self.assertEqual(candidate['link_height_parameter_candidate'],35)
        self.assertEqual(candidate['origin_raw'],[0,0,0])
        self.assertFalse(candidate['property_boundary_verified'])
        self.assertEqual(module.find_candidates(struct.pack('<iQ',26,104)+self.stream()),[])

    def test_no_silent_truncation_trailing_or_tile_payload(self):
        raw=self.envelope()
        for changed in [raw[:-1],raw+b'x',raw[:4]+struct.pack('<I',100)+raw[8:]]:
            self.assertEqual(module.find_candidates(changed),[])
        changed=bytearray(self.stream());struct.pack_into('<i',changed,0,1)
        with self.assertRaises(ValueError):module.decode_parameter_stream(changed)

    def test_plausibility_filters_reject_nonfinite_or_invalid_dimensions(self):
        for offset,fmt,value in [(4,'<d',math.nan),(28,'<d',0),(44,'<i',0),(68,'<d',math.inf),(68,'<d',-1)]:
            raw=bytearray(self.stream());struct.pack_into(fmt,raw,offset,value)
            with self.assertRaises(ValueError):module.decode_parameter_stream(raw)
        raw=bytearray(self.stream());struct.pack_into('<d',raw,68,0)
        self.assertEqual(module.decode_parameter_stream(raw)['link_height_parameter_candidate'],0)

    def test_scan_is_bounded_and_unrelated_suffix_is_not_used(self):
        self.assertEqual(module.find_candidates(bytes(4096)+self.envelope()),[])
        self.assertEqual(module.find_candidates(self.envelope()+b'unrelated'),[])


if __name__=='__main__':unittest.main()
