import importlib.util
import math
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('lift_math', Path(__file__).parent / 'resource-tools/vampir/lift-transform-math.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LiftRotationTests(unittest.TestCase):
    def test_axis_conventions_are_distinct(self):
        k = math.sqrt(.5)
        for angles, expected in [([0, 0, 0], [0, 0, 0, 1]),
                                 ([90, 0, 0], [0, -k, 0, k]),
                                 ([0, 90, 0], [0, 0, k, k]),
                                 ([0, 0, 90], [-k, 0, 0, k])]:
            for actual, wanted in zip(module.rotator_to_quaternion(angles), expected):
                self.assertAlmostEqual(actual, wanted, places=14)

    def test_mixed_rotation_is_unit_length_and_retains_signs(self):
        q = module.rotator_to_quaternion([90, 90, 90])
        for actual, wanted in zip(q, [0, -math.sqrt(.5), 0, math.sqrt(.5)]):
            self.assertAlmostEqual(actual, wanted, places=14)
        self.assertAlmostEqual(sum(v * v for v in q), 1., places=14)

    def test_wrap_uses_degrees_and_negative_angles(self):
        for a, b in zip(module.rotator_to_quaternion([-90, 725, -1440]),
                        module.rotator_to_quaternion([-90, 5, 0])):
            self.assertAlmostEqual(a, b, places=14)

    def test_invalid_or_unverified_angles_rejected(self):
        for value in [[0, 0], [0, 0, 0, 0], [float('nan'), 0, 0], [0, float('inf'), 0], [0, 0, 1e6 + 1]]:
            with self.assertRaises(ValueError):
                module.rotator_to_quaternion(value)

    def test_projection_rotates_each_axis_with_client_signs(self):
        for rotation, point, expected in [([0, 90, 0], [1, 0, 0], [0, 1, 0]),
                                          ([90, 0, 0], [1, 0, 0], [0, 0, 1]),
                                          ([0, 0, 90], [0, 1, 0], [0, 0, -1])]:
            q = module.rotator_to_quaternion(rotation)
            result = module.transform_point(point, [0, 0, 0], q, [1, 1, 1])
            for actual, wanted in zip(result, expected):
                self.assertAlmostEqual(actual, wanted, places=14)

    def test_scale_precedes_rotation_and_translation_including_negative_scale(self):
        q = module.rotator_to_quaternion([0, 90, 0])
        result = module.transform_point([1, 2, 3], [10, 20, 30], q, [-2, 3, 4])
        for actual, wanted in zip(result, [4, 18, 42]):
            self.assertAlmostEqual(actual, wanted, places=14)
        self.assertEqual(module.transform_point([5, 6, 7], [1, 2, 3], q, [0, 0, 0]), [1, 2, 3])

    def test_projection_rejects_nonunit_or_malformed_input(self):
        for point, q in [([0, 0], [0, 0, 0, 1]), ([0, 0, float('nan')], [0, 0, 0, 1]), ([1, 2, 3], [0, 0, 0, 2])]:
            with self.assertRaises(ValueError):
                module.transform_point(point, [0, 0, 0], q, [1, 1, 1])


if __name__ == '__main__':
    unittest.main()
