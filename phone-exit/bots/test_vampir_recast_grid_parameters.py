"""Exact boundary/grid consistency; avoid rounding cooked tile widths."""
import importlib.util
import math
import struct
import unittest
from pathlib import Path
HERE=Path(__file__).parent/'resource-tools/vampir'
def load(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
builder=load('grid_parameter_builder_tests','build-recast-grid-parameter-evidence.py')
audit=load('grid_parameter_audit_tests','audit-recast-grid-parameters.py')

def tile(x,z,width,origin):
    raw=bytearray(88);struct.pack_into('<ii',raw,8,x,z)
    struct.pack_into('<6d',raw,40,origin[0]+x*width,0.,origin[2]+z*width,origin[0]+(x+1)*width,0.,origin[2]+(z+1)*width)
    return bytes(raw)

class GridParameterTests(unittest.TestCase):
    def test_exact_width_preserves_negative_boundary_cell(self):
        width=1000.0000133514404;origin=[0.,0.,0.];raw=tile(-141,-136,width,origin)
        precise=builder.grid_comparison(raw,origin,[width,width]);rounded=builder.grid_comparison(raw,origin,[1000.,1000.])
        self.assertEqual(precise['max_error'],0.);self.assertEqual(precise['minimum_maps_to'],[-141,-136])
        self.assertEqual(rounded['minimum_maps_to'],[-142,-137]);self.assertTrue(rounded['minimum_grid_mismatch'])

    def test_positive_negative_and_nonzero_origins_match_independent_audit(self):
        width=1000.0000133514404;origin=[123.,0.,-456.]
        for x,z in [(0,0),(17,-4),(-141,102)]:
            raw=tile(x,z,width,origin);record={name:builder.grid_comparison(raw,o,w) for name,o,w in
                [('candidate',origin,[width,width]),('rounded',[0.,0.,0.],[1000.,1000.])]}
            audit.check_grid_record(raw,record,origin,[width,width])
            record['candidate']['max_error']=1.
            with self.assertRaises(AssertionError):audit.check_grid_record(raw,record,origin,[width,width])

    def test_small_boundary_error_is_not_silently_treated_as_exact(self):
        raw=tile(-2,3,1000.,[0.,0.,0.]);changed=bytearray(raw)
        struct.pack_into('<d',changed,40,math.nextafter(-2000.,-math.inf))
        result=builder.grid_comparison(bytes(changed),[0.,0.,0.],[1000.,1000.])
        self.assertGreater(result['max_error'],0.);self.assertTrue(result['minimum_grid_mismatch'])

if __name__=='__main__':unittest.main()
