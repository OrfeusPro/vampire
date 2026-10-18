"""Independent surface math, candidate admission, and native input bounds."""
import copy
import importlib.util
import math
import struct
import unittest
from pathlib import Path
HERE=Path(__file__).parent/'resource-tools/vampir'
def load(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
audit=load('projection_audit_tests','audit-recast-projection.py')
native=load('projection_bound_tests','recast-projection-emulator.py')

def slope():
    raw=bytearray(208);struct.pack_into('<H',raw,0,7)
    for off,value in [(4,1),(6,3),(18,1),(22,1)]:struct.pack_into('<H',raw,off,value)
    for i,vertex in enumerate([(0.,0.,0.),(2.,2.,0.),(0.,4.,2.)]):struct.pack_into('<3d',raw,88+24*i,*vertex)
    struct.pack_into('<3H',raw,164,0,1,2);struct.pack_into('<HBB',raw,188,1,3,1)
    struct.pack_into('<HHBB',raw,192,0,0,0,1);raw[200:204]=bytes([0,1,2,0])
    return bytes(raw)

class ProjectionTests(unittest.TestCase):
    def test_triangle_height_and_xz_edge_clamp(self):
        raw=slope()
        self.assertEqual(audit.closest_point(raw,0,[.5,90.,.5]),[.5,1.5,.5])
        self.assertEqual(audit.closest_point(raw,0,[-1.,90.,1.]),[0.,2.,1.])
        self.assertIsNone(audit.triangle_height([10.,0.,10.],[(0.,0.,0.),(2.,2.,0.),(0.,4.,2.)]))

    def test_independent_projection_rejects_wrong_height_and_excluded_polygon(self):
        case=dict(name='slope',point=[.5,2.,.5],extents=[1.,1.,1.],grid=dict(origin=[0.,0.,0.],widths=[1000.,1000.]),
            options=dict(include=65535,exclude=0,travel=[1.]*64,entering=[0.]*64),
            result=dict(status=0x40000000,capacity_saturated=False,polygon=[0,0],point_nav=[.5,1.5,.5]))
        self.assertEqual(audit.check_projection([slope()],case,1e-6),1)
        for kind in ['height','exclude']:
            wrong=copy.deepcopy(case)
            if kind=='height':wrong['result']['point_nav'][1]=2.
            else:wrong['options']['exclude']=1
            with self.assertRaises(AssertionError):audit.check_projection([slope()],wrong,1e-6)

    def test_invalid_projection_inputs_fail_before_engine_access(self):
        instance=object.__new__(native.ProjectionEmulator)
        for point,extents in [([0.,0.],[1.,1.,1.]),([0.,math.nan,0.],[1.,1.,1.]),([True,0.,0.],[1.,1.,1.]),
            ([0.,0.,0.],[-1.,1.,1.]),([0.,0.,0.],[1.,1001.,1.])]:
            with self.assertRaises(ValueError):instance.project(point,extents)

    def test_zero_extents_are_valid_explicit_inputs_for_native_minimum_clamp(self):
        native.validate_point([0.,0.,0.],[0.,0.,0.])
        with self.assertRaises(ValueError):native.validate_point([0.,0.,1e9+1],[0.,0.,0.])

if __name__=='__main__':unittest.main()
