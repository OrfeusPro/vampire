"""Source checks cannot turn rotation assumptions or navigation inputs into paths."""
import importlib.util,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('readiness',Path(__file__).parent/'resource-tools/vampir/map-readiness.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class ReadinessTests(unittest.TestCase):
    def test_proven_rotation_changes_geometry_status_without_certifying_navigation(self):
        report=module.assess([self.box(Yaw='30')],[],set(),rotation_verified=True)
        self.assertEqual(report['summary']['rotated_unverified'],0)
        self.assertEqual(report['summary']['rotated_verified'],1)
        self.assertTrue(report['summary']['rotation_pivot_verified'])
        self.assertFalse(report['summary']['navigation_ready'])
        self.assertEqual(report['summary']['routes_verified'],0)
        self.assertEqual(len(report['verified_rotated_boxes'][0]['polygon']),4)

    def box(self,**values):
        return dict(dict(Id='b',AreaBoxMinPos='x=0,y=0',AreaBoxMaxPos='x=10,y=20',Yaw='0'),**values)

    def test_rotation_preserves_raw_record_without_inventing_pivot_or_polygon(self):
        row=self.box(Yaw='90')
        report=module.assess([row],[],set())
        self.assertEqual(report['summary']['rotated_unverified'],1)
        rotation=report['rotated_boxes'][0]
        self.assertEqual(rotation['record'],row)
        self.assertIsNone(rotation['polygon'])
        self.assertFalse(rotation['rotation_pivot_verified'])
        self.assertFalse(report['summary']['navigation_ready'])

    def test_inverted_malformed_and_nonfinite_boxes_are_not_silently_fixed(self):
        rows=[self.box(AreaBoxMinPos='x=30,y=0'),self.box(Yaw='nan'),self.box(AreaBoxMaxPos='x=2garbage,y=3'),self.box(AreaBoxMaxPos='x=1e3,y=2')]
        result=module.assess(rows,[],set())
        self.assertEqual(result['summary']['invalid_extents'],3)
        self.assertEqual(result['summary']['zero_yaw_valid'],1)
        self.assertEqual(result['invalid_boxes'][0]['record']['AreaBoxMinPos'],'x=30,y=0')

    def test_valid_route_endpoints_are_inputs_only_and_unknown_world_is_preserved(self):
        row=dict(caseKey='case',worldInfoId='unknown',navFileName='test_Nav.bin',sx='0',sy='1',sz='2',ex='3',ey='4',ez='5')
        report=module.assess([], [row,dict(row,caseKey='bad',ex='inf')],{'other'})
        self.assertEqual(report['summary']['route_world_missing'],2)
        self.assertEqual(report['summary']['route_invalid_coordinates'],1)
        self.assertEqual(report['summary']['routes_verified'],0)
        self.assertEqual(report['summary']['nav_files'],{'test_Nav.bin':2})
        self.assertTrue(report['route_inputs'][0]['input_coordinates_finite'])
        self.assertIsNone(report['route_inputs'][0]['walkable'])
        self.assertFalse(report['route_inputs'][0]['path_verified'])
        self.assertEqual(report['route_inputs'][0]['record'],row)

if __name__=='__main__':unittest.main()
