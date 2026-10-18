import copy
import importlib.util
import math
import unittest
from pathlib import Path
HERE=Path(__file__).parent/'resource-tools/vampir'
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
native=load('selection_input_tests','recast-filter-selection-emulator.py')
model=load('selection_order_tests','build-recast-filter-selection-evidence.py')

class FilterSelectionTests(unittest.TestCase):
    def case(self):
        before=dict(travel_costs=[7.]*64,entering_costs=[4.]*64,minimum_cost=7.,include_flags=123,exclude_flags=8)
        after=copy.deepcopy(before);after['travel_costs'][10:14]=[1.]*4;after['minimum_cost']=1.
        events=[dict(kind='query_cache_stub',field=f,base_state=copy.deepcopy(before)) for f in model.FIELDS]
        events += [dict(kind='travel_setter',area_id=i,value=1.) for i in range(10,14)]
        return dict(entry='lifecycle',states={},base_present=True,before=before,after=after,events=events,runtime_verified=False)

    def test_only_four_base_costs_change_and_polygon_masks_are_preserved(self):
        value=self.case();model.validate_case(value)
        for key in ['entering_costs','include_flags','exclude_flags']:
            changed=copy.deepcopy(value)
            if key=='entering_costs':changed['after'][key][0]=100.
            else:changed['after'][key]=0
            with self.assertRaises(ValueError):model.validate_case(changed)

    def test_queries_cannot_observe_a_later_reset_or_move_after_it(self):
        changed=self.case();changed['events'][0]['base_state']=copy.deepcopy(changed['after'])
        with self.assertRaises(ValueError):model.validate_case(changed)
        changed=self.case();changed['events'].append(changed['events'].pop(0))
        with self.assertRaises(ValueError):model.validate_case(changed)

    def test_class_field_substitution_cannot_pass_selection_validation(self):
        changed=self.case();changed['events'][0]['field']='ShortPath'
        with self.assertRaises(ValueError):model.validate_case(changed)
        changed=self.case();changed['runtime_verified']=True
        with self.assertRaises(ValueError):model.validate_case(changed)

    def test_native_input_bounds_do_not_allow_undefined_states_or_float_values(self):
        instance=object.__new__(native.FilterSelectionEmulator)
        for args in [dict(entry='Unknown'),dict(states={'Other':'present'}),dict(states={'Default':'guessed'}),
                     dict(costs={64:1.}),dict(costs={-1:1.}),dict(costs={1:math.nan}),dict(costs={1:math.inf}),
                     dict(costs={1:-1.}),dict(base_present=1),dict(callback_flag=1)]:
            with self.assertRaises(ValueError):instance.run(**args)

if __name__=='__main__':unittest.main()
