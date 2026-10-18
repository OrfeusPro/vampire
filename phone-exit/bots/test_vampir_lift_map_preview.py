import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).parent / 'resource-tools/vampir'


def module(name, file):
    s = importlib.util.spec_from_file_location(name, HERE / file)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


preview = module('lift_preview_test', 'build-lift-map-preview.py')
model = module('lift_preview_math_test', 'lift-transform-math.py')


class LiftPreviewTests(unittest.TestCase):
    def fixture(self):
        return dict(RelativeLocation=[10, 20, 30], RelativeRotation=[0, 90, 0], RelativeScale3D=[2, 3, 4]), [dict(properties=dict(Left=[1, 0, 1], Right=[0, 1, 2], Direction=0))]

    def test_projection_preserves_height_and_conditional_status(self):
        p, links = self.fixture()
        r = preview.calculate(p, links, model)
        edge = r['calculated_links'][0]
        for actual, expected in zip(edge['left'], [10, 22, 34]):
            self.assertAlmostEqual(actual, expected)
        for actual, expected in zip(edge['right'], [7, 20, 38]):
            self.assertAlmostEqual(actual, expected)
        self.assertEqual(edge['direction'], 0)
        self.assertIsNone(edge['walkable'])
        self.assertFalse(edge['world_coordinates_verified'])
        self.assertFalse(r['world_transform_verified'])

    def test_omitted_rotation_or_scale_is_not_silently_defaulted(self):
        for name in ['RelativeRotation', 'RelativeScale3D']:
            p, links = self.fixture()
            del p[name]
            result = preview.calculate(p, links, model)
            self.assertEqual(result['calculated_links'], [])
            self.assertIn(name, result['missing'])

    def test_missing_array_and_missing_endpoint_do_not_make_edges(self):
        p, links = self.fixture()
        self.assertIn('PointLinks', preview.calculate(p, None, model)['missing'])
        self.assertEqual(preview.calculate(p, [], model)['calculated_links'], [])
        del links[0]['properties']['Right']
        result = preview.calculate(p, links, model)
        self.assertEqual(result['calculated_links'], [])
        self.assertIn('PointLinks endpoints', result['missing'])

    def test_verified_initial_scale_is_separate_and_does_not_mutate_raw_placement(self):
        p, links = self.fixture()
        del p['RelativeScale3D']
        result = preview.calculate(p, links, model, {'scene_scale_initial': [1, 1, 1]})
        self.assertNotIn('RelativeScale3D', p)
        self.assertEqual(result['initial_fields'], {'RelativeScale3D': [1, 1, 1]})
        self.assertEqual(len(result['calculated_links']), 1)
        self.assertIsNone(result['calculated_links'][0]['walkable'])

    def test_explicit_zero_scale_and_empty_array_override_native_initial_values(self):
        p, links = self.fixture()
        p['RelativeScale3D'] = [0, 0, 0]
        initial = {'scene_scale_initial': [1, 1, 1], 'native_point_links_initial': links}
        result = preview.calculate(p, links, model, initial)
        self.assertEqual(result['calculated_links'][0]['left'], p['RelativeLocation'])
        self.assertEqual(result['initial_fields'], {})
        empty = preview.calculate(p, [], model, initial)
        self.assertEqual(empty['calculated_links'], [])
        self.assertEqual(empty['initial_fields'], {})

    def test_missing_array_can_inherit_but_rotation_stays_unknown(self):
        p, links = self.fixture()
        initial = {'native_point_links_initial': links, 'RelativeRotation': [0, 0, 0]}
        inherited = preview.calculate(p, None, model, initial)
        self.assertEqual(inherited['initial_fields']['PointLinks'], links)
        self.assertEqual(len(inherited['calculated_links']), 1)
        del p['RelativeRotation']
        missing = preview.calculate(p, None, model, initial)
        self.assertEqual(missing['calculated_links'], [])
        self.assertIn('RelativeRotation', missing['missing'])


if __name__ == '__main__':
    unittest.main()
