import importlib.util,struct,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('lift_blueprints',Path(__file__).parent/'resource-tools/vampir/build-lift-blueprints.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class LiftBlueprintTests(unittest.TestCase):
    def fixture(self,super_index=-1,name_index=1):
        asset=bytearray(256);struct.pack_into('<i',asset,32,4);struct.pack_into('<iiii',asset,68,1,96,1,192);struct.pack_into('<i',asset,100,super_index);struct.pack_into('<i',asset,212,name_index)
        parsed=dict(names=['Decoy_Lift','ActualSuperclass'],exports=[dict(index=1,name='MisleadingName',type='BlueprintGeneratedClass')])
        return bytes(asset),parsed
    def test_superclass_comes_from_import_not_filename_or_class_name(self):
        asset,parsed=self.fixture();result=module.class_parent(asset,parsed)
        self.assertEqual(result['super_name'],'ActualSuperclass')
        self.assertEqual(result['super_index'],-1)
        self.assertEqual(result['import_offset'],192)
    def test_unresolved_local_or_outside_superclass_rejected(self):
        for index in [0,1,-2]:
            with self.assertRaises(ValueError):module.class_parent(*self.fixture(super_index=index))
    def test_invalid_name_or_ambiguous_class_cannot_choose_a_parent(self):
        with self.assertRaises(ValueError):module.class_parent(*self.fixture(name_index=20))
        asset,parsed=self.fixture();parsed['exports'].append(dict(index=2,type='BlueprintGeneratedClass'))
        with self.assertRaises(ValueError):module.class_parent(asset,parsed)
if __name__=='__main__':unittest.main()
