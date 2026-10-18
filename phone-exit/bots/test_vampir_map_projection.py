"""Independent historical icon regions catch axis/sign/scale projection mistakes."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('map_projection', Path(__file__).parent / 'resource-tools/vampir/build-map-projection.py')
projection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(projection)


class MapProjectionTests(unittest.TestCase):
    # Terrain-derived frame registration, independent of the client XY positions.
    matrix = [[1.500731660368642, .00018841724018326978, 6044.366013825543],
              [-.00018841724018326978, 1.500731660368642, 6241.531909622766]]
    regions = [(113510, 99950, [625, 340, 665, 383]),
               (113510, 121697, [630, 588, 657, 616]),
               (98805, 98558, [465, 332, 495, 361]),
               (112210, 117750, [614, 540, 645, 571]),
               (106220, 109605, [548, 450, 579, 483]),
               (106225, 102825, [549, 377, 580, 408]),
               (107004, 96866, [556, 308, 587, 341])]

    def test_native_formula_passes_all_seven_unfitted_regions(self):
        for x, y, box in self.regions:
            self.assertTrue(projection.inside(projection.screen_point(projection.project(x, y), self.matrix), box))

    def test_wrong_axis_orientation_and_extent_rejected_by_independent_regions(self):
        for mutation in [lambda x, y: projection.project(y, x),
                         lambda x, y: projection.project(-x, y),
                         lambda x, y: projection.project(x, -y),
                         lambda x, y: projection.project(x, y, ground=307500)]:
            self.assertFalse(all(projection.inside(projection.screen_point(mutation(x, y), self.matrix), box)
                                 for x, y, box in self.regions))

    def test_invalid_parameters_do_not_emit_nan_or_infinite_coordinates(self):
        for kwargs in [dict(ground=0), dict(ground=-1), dict(size=(0, 10240)), dict(center=(float('nan'), 0))]:
            with self.assertRaises(ValueError):
                projection.project(100, 200, **kwargs)

    def test_singular_terrain_transform_rejected(self):
        with self.assertRaises(ValueError):
            projection.screen_point([1, 2], [[1, 1, 0], [1, 1, 0]])


if __name__ == '__main__':
    unittest.main()
