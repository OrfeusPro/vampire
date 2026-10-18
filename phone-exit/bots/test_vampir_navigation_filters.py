import importlib.util,math,struct,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('filter_decode_tests',Path(__file__).parent/'resource-tools/vampir/decode-navigation-filter-resources.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
IMPORTS=[dict(index=-1,name='NavArea_Default',outer=-2),dict(index=-2,name='/Script/NavigationSystem',outer=0)]

class NavigationFilterTests(unittest.TestCase):
    def fixture(self,cost=.5,bools=b'\0\1\0',reference=-1):
        return struct.pack('<HiHBif',0x300,1,0xd80,4,reference,cost)+bools+b'ABCD'

    def test_native_zero_mask_and_override_flags_preserve_explicit_values(self):
        result=module.decode(self.fixture(),IMPORTS);p=result['areas'][0]['properties']
        self.assertEqual(p['AreaClass'],'/Script/NavigationSystem.NavArea_Default')
        self.assertEqual(p['TravelCostOverride'],.5);self.assertEqual(p['EnteringCostOverride'],0)
        self.assertTrue(p['bOverrideTravelCost']);self.assertFalse(p['bIsExcluded'])
        self.assertEqual(result['uninterpreted_suffix_hex'],b'ABCD'.hex())

    def test_omitted_values_are_not_filled_with_constructor_defaults(self):
        raw=struct.pack('<HiHi',0x300,1,0x300,-1)+bytes(4)
        p=module.decode(raw,IMPORTS)['areas'][0]['properties']
        self.assertEqual(set(p),{'AreaClassRaw','AreaClass'})
        raw=struct.pack('<HiHB',0x300,1,0x380,1)+bytes(4)
        self.assertIsNone(module.decode(raw,IMPORTS)['areas'][0]['properties']['AreaClass'])

    def test_malformed_fields_counts_bools_and_nonfinite_costs_fail(self):
        for raw in [self.fixture(math.nan),self.fixture(bools=b'\2\1\0'),self.fixture()[:-1],struct.pack('<Hi',0x300,1001),struct.pack('<HiH',0x300,1,0xf00),struct.pack('<Hi',0x301,1)]:
            with self.assertRaises(ValueError):module.decode(raw,IMPORTS)

    def test_class_import_must_exist_and_cannot_cycle(self):
        for raw,imports in [(self.fixture(reference=1),IMPORTS),(self.fixture(reference=-3),IMPORTS),
            (self.fixture(),[dict(index=-1,name='a',outer=-2),dict(index=-2,name='b',outer=-1)])]:
            with self.assertRaises(ValueError):module.decode(raw,imports)

if __name__=='__main__':unittest.main()
