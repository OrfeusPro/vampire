import importlib.util,math,struct,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('coordinate_math',Path(__file__).parent/'resource-tools/vampir/recast-coordinate-math.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class RecastCoordinateTests(unittest.TestCase):
    def test_world_axes_and_inverse(self):
        self.assertEqual(module.world_to_nav([10,20,30]),[-10,30,-20])
        self.assertEqual(module.nav_to_world([-10,30,-20]),[10,20,30])

    def test_signed_zero_roundtrip_is_lossless(self):
        for value in [[0.,-0.,0.],[-0.,0.,-0.],[1e6,-1e6,1e-12]]:
            self.assertEqual(struct.pack('<3d',*value),struct.pack('<3d',*module.nav_to_world(module.world_to_nav(value))))

    def test_invalid_coordinate_is_rejected(self):
        for value in [[0,0],[True,0,0],[math.nan,0,0],[0,math.inf,0],['1',2,3]]:
            with self.assertRaises(ValueError):module.world_to_nav(value)


if __name__=='__main__':unittest.main()
