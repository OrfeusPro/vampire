import importlib.util,math,unittest
from pathlib import Path
HERE=Path(__file__).parent/'resource-tools/vampir'
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
geometry=load('nearest_geometry_tests','build-recast-nearest-candidates.py')
emulator=load('nearest_argument_tests','recast-nearest-emulator.py')

class NearestGeometryTests(unittest.TestCase):
    def test_tile_selection_includes_touching_bounds_but_rejects_other_height(self):
        bounds=[0,10,0,100,20,100]
        self.assertTrue(geometry.intersects([-1,15,50],[1,0,1],bounds))
        self.assertFalse(geometry.intersects([-1.01,15,50],[1,0,1],bounds))
        self.assertFalse(geometry.intersects([50,0,50],[1,9,1],bounds))

    def test_attachment_radius_is_horizontal_and_includes_exact_boundary(self):
        self.assertTrue(geometry.radial_accept([0,1000,0],[3,-1000,4],5))
        self.assertFalse(geometry.radial_accept([0,0,0],[3,0,4.001],5))

    def test_invalid_inputs_fail_before_native_execution(self):
        instance=object.__new__(emulator.NearestEmulator)
        for point,extent in [([math.nan,0,0],[1,1,1]),([0,0,0],[-1,1,1]),([0,0],[1,1,1]),([0,0,0],[1,math.inf,1])]:
            with self.assertRaises(ValueError):instance.nearest(point,extent)

if __name__=='__main__':unittest.main()
