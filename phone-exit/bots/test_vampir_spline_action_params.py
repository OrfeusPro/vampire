import importlib.util,struct,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('spline',Path(__file__).parent/'resource-tools/vampir/decode-spline-action-params.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class SplineActionParamsTests(unittest.TestCase):
    def decode(self,raw):return module.decode(module.canvas.Reader(raw))
    def test_explicit_duration_and_blend_do_not_establish_units_or_defaults(self):
        row=self.decode(struct.pack('<HHff',0x200,0x301,1.8,1.0))
        self.assertAlmostEqual(row['properties']['Duration'],1.8,places=5)
        self.assertEqual(row['properties']['BlendExp'],1.)
        self.assertNotIn('EasingFunc',row['properties'])
        self.assertIsNone(row['time_unit'])
        self.assertFalse(row['runtime_effect_verified'])
        self.assertEqual(row['serialized_size'],12)
    def test_false_is_distinct_from_omitted_and_zero_struct_not_filled(self):
        row=self.decode(struct.pack('<HB',0x305,0))
        self.assertIs(row['properties']['FadeEnabled'],False)
        zero=module.decode(module.canvas.Reader(b''),True)
        self.assertTrue(zero['serialized_zero'])
        self.assertEqual(zero['properties'],{})
    def test_wide_string_and_raw_reference_are_preserved(self):
        text='Лифт'.encode('utf-16le')+b'\0\0'
        row=self.decode(struct.pack('<Hi',0x303,-5)+text)
        self.assertEqual(row['properties']['MontageName'],'Лифт')
        row=self.decode(struct.pack('<Hi',0x311,-4))
        self.assertEqual(row['properties']['FinishEffect'],-4)
    def test_unknown_truncated_bad_bool_or_nonfinite_fails(self):
        for raw in [struct.pack('<H',0x316),struct.pack('<Hf',0x300,float('inf')),struct.pack('<HB',0x305,2),struct.pack('<Hi',0x303,99)]:
            with self.assertRaises(ValueError):self.decode(raw)
if __name__=='__main__':unittest.main()
