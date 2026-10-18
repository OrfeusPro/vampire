"""Bounds and independent corridor-audit regressions for offline native search."""
import copy
import importlib.util
import math
import struct
import unittest
from pathlib import Path
HERE=Path(__file__).parent/'resource-tools/vampir'
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
native=load('path_query_bounds','recast-path-query-emulator.py')
audit=load('path_query_audit_tests','audit-recast-path-query.py')

def fixture():
    # Two squares sharing edge 1->2, each with a different area.
    vertices=[(0.,0.,0.),(2.,0.,0.),(2.,0.,2.),(0.,0.,2.),(4.,0.,0.),(4.,0.,2.)]
    raw=bytearray(88+len(vertices)*24+64)
    struct.pack_into('<HHHH',raw,0,7,0,2,len(vertices))
    for i,v in enumerate(vertices):struct.pack_into('<3d',raw,88+i*24,*v)
    for i,ids,neighbors in [(0,[0,1,2,3],[0,2,0,0]),(1,[1,4,5,2],[0,0,0,1])]:
        pos=88+len(vertices)*24+32*i
        struct.pack_into('<4H',raw,pos+4,*ids);struct.pack_into('<4H',raw,pos+16,*neighbors)
        struct.pack_into('<HBB',raw,pos+28,1,4,i+1)
    case=dict(name='two_squares',start=0,end=1,settings={'travel':[2.]*64,'entering':[3.]*64},
        result=dict(status=0x40000000,corridor=[0,1],segment_costs=[0.,7.],total_cost=7.))
    return bytes(raw),case

class PathQueryTests(unittest.TestCase):
    def test_independent_cost_includes_entering_and_final_leg(self):
        raw,case=fixture();self.assertEqual(audit.check_corridor(raw,case),2)
        for field in ['segment_costs','total_cost']:
            broken=copy.deepcopy(case)
            if field=='segment_costs':broken['result'][field]=[0.,6.]
            else:broken['result'][field]=6.
            with self.assertRaises(AssertionError):audit.check_corridor(raw,broken)

    def test_independent_audit_rejects_false_partial_and_blocked_neighbor(self):
        raw,case=fixture();case['result']['status']|=0x40
        with self.assertRaises(AssertionError):audit.check_corridor(raw,case)
        case['result']['status']=0x40000000;case['settings']['exclude']=1
        with self.assertRaises(AssertionError):audit.check_corridor(raw,case)

    def test_endpoints_and_limits_fail_before_native_execution(self):
        raw,_=fixture();instance=object.__new__(native.PathQueryEmulator)
        for start,end in [(-1,0),(0,2),(True,1),(0,'1')]:
            with self.assertRaises(ValueError):instance.search(raw,start,end)
        for limit in [-1.,math.nan,math.inf]:
            with self.assertRaises(ValueError):instance.search(raw,0,1,cost_limit=limit)

    def test_unreviewed_native_execution_is_rejected(self):
        instance=object.__new__(native.PathQueryEmulator);instance.x=None;instance.allowed=[]
        for address in [0x14523c6c0,0x14523c77a,0x1452457b0,0x1487a2e19]:
            with self.assertRaises(ValueError):instance.guard(None,address,1,None)

if __name__=='__main__':unittest.main()
