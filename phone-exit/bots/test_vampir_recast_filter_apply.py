import importlib.util,math,unittest
from pathlib import Path
HERE=Path(__file__).parent/'resource-tools/vampir'
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
emulator=load('filter_apply_input_tests','recast-filter-apply-emulator.py')
model=load('filter_apply_model_tests','build-recast-filter-apply-evidence.py')

class FilterApplyTests(unittest.TestCase):
    def area(self,**changes):
        result=dict(AreaClass='a',TravelCostOverride=1.,EnteringCostOverride=0.,bIsExcluded=False,bOverrideTravelCost=False,bOverrideEnteringCost=False);result.update(changes);return result

    def test_omitted_or_invalid_values_cannot_be_filled_for_native_execution(self):
        instance=object.__new__(emulator.FilterApplyEmulator)
        for area in [{},self.area(TravelCostOverride=math.nan),self.area(EnteringCostOverride=1e39),self.area(bIsExcluded=1),self.area(AreaClass=12)]:
            with self.assertRaises(ValueError):instance.apply([area],{'a':11})

    def test_area_map_and_flags_cannot_wrap_to_other_ids(self):
        instance=object.__new__(emulator.FilterApplyEmulator)
        for ids,include,exclude in [({'a':64},65535,0),({'a':-1},65535,0),({'a':11,'b':11},65535,0),({'a':11},65536,0),({'a':11},65535,-1)]:
            with self.assertRaises(ValueError):instance.apply([],ids,include,exclude)

    def test_inactive_override_values_leave_an_existing_base_cost_unchanged(self):
        before=dict(travel_costs=[42.]*64,entering_costs=[7.]*64,minimum_cost=42.,include_flags=65535,exclude_flags=0)
        result=model.model_apply(before,[self.area()],{'a':11},65535,0)
        self.assertEqual(result,before)
        self.assertEqual(model.model_apply(before,[self.area(AreaClass='unregistered',bIsExcluded=True)],{'a':11},65535,0),before)

    def test_exclusion_skips_other_overrides_and_record_order_is_preserved(self):
        before=dict(travel_costs=[1.]*64,entering_costs=[0.]*64,minimum_cost=1.,include_flags=65535,exclude_flags=0)
        excluded=self.area(bIsExcluded=True,bOverrideTravelCost=True,bOverrideEnteringCost=True,TravelCostOverride=2.,EnteringCostOverride=3.)
        override=self.area(bOverrideTravelCost=True,TravelCostOverride=2.)
        result=model.model_apply(before,[excluded],{'a':11},65535,0)
        self.assertEqual(result['travel_costs'][11],model.FLOAT_MAX);self.assertEqual(result['entering_costs'][11],0)
        self.assertEqual(model.model_apply(before,[excluded,override],{'a':11},65535,0)['travel_costs'][11],2.)
        self.assertEqual(model.model_apply(before,[override,excluded],{'a':11},65535,0)['travel_costs'][11],model.FLOAT_MAX)

if __name__=='__main__':unittest.main()
