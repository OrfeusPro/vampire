import importlib.util
import math
import unittest
from pathlib import Path
p=Path(__file__).parent/'resource-tools/vampir/recast-route-filter-emulator.py'
s=importlib.util.spec_from_file_location('route_filter_bound_tests',p);native=importlib.util.module_from_spec(s);s.loader.exec_module(native)

class RouteFilterBoundsTests(unittest.TestCase):
    def test_coordinate_inputs_cannot_enter_native_code_with_invalid_points(self):
        instance=object.__new__(native.RouteFilterBranchEmulator)
        for point in [None,[],[1,2],[1,2,3,4],[0,0,math.nan],[0,math.inf,0],[True,0,0],[0,0,'3'],[1e9+1,0,0]]:
            with self.assertRaises(ValueError):instance.select(point,[0,0,0])
            with self.assertRaises(ValueError):instance.select([0,0,0],point)

    def test_native_branch_guard_rejects_code_outside_exact_scalar_range(self):
        instance=object.__new__(native.RouteFilterBranchEmulator)
        for address,size in [(native.BEGIN-1,1),(native.END,1),(native.END-1,2)]:
            with self.assertRaises(ValueError):instance.guard(None,address,size,None)
        instance.guard(None,native.BEGIN,8,None)

if __name__=='__main__':unittest.main()
