import importlib.util
import math
import unittest
from pathlib import Path
HERE=Path(__file__).parent/'resource-tools/vampir'
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
native=load('base_filter_input_tests','recast-base-filter-emulator.py')
model=load('base_filter_model_tests','build-recast-base-filter-evidence.py')

class BaseFilterTests(unittest.TestCase):
    def area(self,**changes):
        area=dict(area_id=12,class_state='present',travel=.5,entering=-2.);area.update(changes);return area
    def state(self,areas,**changes):
        args=dict(areas=areas,owner_5bc=2048.,owner_5d0=0,owner_644=1.,blocked_flags=0);args.update(changes);return model.expected_state(**args)

    def test_native_bounds_require_explicit_records_and_finite_float32(self):
        for area in [{},self.area(area_id=64),self.area(area_id=-1),self.area(area_id=True),self.area(class_state='guess'),self.area(travel=math.nan),self.area(entering=math.inf)]:
            with self.assertRaises(ValueError):native.validate_inputs([area],2048.,0,1.,0)
        for args in [(0,0,1.,65536),(0,-1,1.,0),(math.inf,0,1.,0),(0,0,math.nan,0),(0,0,True,0)]:
            with self.assertRaises(ValueError):native.validate_inputs([], *args)
        with self.assertRaises(ValueError):native.validate_inputs([self.area()]*65,2048.,0,1.,0)

    def test_base_CDO_costs_are_not_query_override_clamps(self):
        state=self.state([self.area()])
        self.assertEqual(state['travel_costs'][12],.5)
        self.assertEqual(state['entering_costs'][12],-2.)
        self.assertEqual(state['minimum_cost'],.5)

    def test_repeated_areas_preserve_order_and_minimum_lower_bound(self):
        state=self.state([self.area(),self.area(travel=7.,entering=3.)])
        self.assertEqual(state['travel_costs'][12],7.)
        self.assertEqual(state['entering_costs'][12],3.)
        self.assertEqual(state['minimum_cost'],.5)
        skipped=self.state([self.area(class_state='null_cdo'),self.area(class_state='null_class')])
        self.assertEqual(skipped['travel_costs'][12],1.)
        self.assertEqual(skipped['entering_costs'][12],0.)

    def test_owner_and_mask_fields_keep_x86_conversion_semantics(self):
        state=self.state([],owner_5bc=2048.75,owner_5d0=2048,owner_644=.999,blocked_flags=0x25)
        self.assertEqual(state['owner_5bc_truncated'],2048)
        self.assertEqual(state['impl_flag428'],1)
        self.assertEqual(state['include_flags'],65535^0x25)
        self.assertEqual(state['exclude_flags'],0)
        self.assertEqual(state['impl_double410'],native.float32(.999))
        self.assertEqual(self.state([],owner_5bc=2147483648.)['owner_5bc_truncated'],-2147483648)

if __name__=='__main__':unittest.main()
