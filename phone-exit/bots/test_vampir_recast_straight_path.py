"""Independent funnel corners, ordered crossings and native boundary inputs."""
import importlib.util
import math
import unittest
from pathlib import Path
HERE=Path(__file__).parent/'resource-tools/vampir'
def load(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
audit=load('straight_geometry_tests','audit-recast-straight-path.py')
native=load('straight_bound_tests','recast-straight-path-emulator.py')

class StraightPathTests(unittest.TestCase):
    def test_turn_uses_inner_portal_corner(self):
        start=[0.,0.,0.];end=[3.,0.,3.]
        portals=[([1.,0.,1.],[1.,0.,-1.]),([2.,0.,1.],[3.,0.,1.])]
        self.assertEqual(audit.funnel(start,end,portals),[start,[2.,0.,1.],end])

    def test_open_corridor_needs_no_extra_turn_and_degenerate_gate_is_preserved(self):
        start=[0.,0.,0.];end=[4.,0.,0.]
        self.assertEqual(audit.funnel(start,end,[([2.,0.,1.],[2.,0.,-1.])]),[start,end])
        gate=[2.,0.,1.]
        self.assertEqual(audit.funnel(start,end,[(gate,gate)]),[start,gate,end])

    def test_area_crossing_points_cannot_shortcut_or_go_backwards(self):
        line=[[0.,0.,0.],[2.,0.,0.],[2.,0.,2.]]
        audit.on_ordered_polyline([[1.,0.,0.],[2.,0.,1.]],line)
        for points in [[[1.,0.,1.]],[[2.,0.,1.],[1.,0.,0.]]]:
            with self.assertRaises(AssertionError):audit.on_ordered_polyline(points,line)

    def test_invalid_corridor_endpoints_and_options_fail_before_engine_access(self):
        instance=object.__new__(native.StraightPathEmulator);instance.poly_counts=[1,1]
        for corridor,start,end,options in [([],[0,0,0],[1,0,0],0),([[0,1]],[0,0,0],[1,0,0],0),
            ([[0,0]],[0,math.inf,0],[1,0,0],0),([[0,0]],[0,0,0],[1,0,0],3)]:
            with self.assertRaises(ValueError):instance.straight(corridor,start,end,options)

if __name__=='__main__':unittest.main()
