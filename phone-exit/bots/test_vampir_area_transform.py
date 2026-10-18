import importlib.util,json,tempfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('area_transform',Path(__file__).parent/'resource-tools/vampir/area-transform-math.py')
model=importlib.util.module_from_spec(spec);spec.loader.exec_module(model)

class AreaTransformTests(unittest.TestCase):
    def test_missing_evidence_does_not_enable_geometry_and_changed_model_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            self.assertIsNone(model.validated_evidence(root,'tables'))
            (root/'code-clues').mkdir()
            evidence=dict(summary=dict(rotation_pivot_verified=True,rotation_direction_verified=True,point_samples=1),model_sha256='changed',tables_sha256='tables')
            (root/'code-clues/area-box-transform.json').write_text(json.dumps(evidence),'utf-8')
            with self.assertRaises(ValueError):model.validated_evidence(root,'tables')

    def test_nonsquare_rotation_keeps_translated_center_and_positive_xy_direction(self):
        corners=model.vertices([100.,200.],[120.,260.],90)
        for actual,expected in zip(corners,[[140,220],[140,240],[80,240],[80,220]]):
            for a,b in zip(actual,expected):self.assertAlmostEqual(a,b,places=5)
        self.assertAlmostEqual(sum(v[0] for v in corners)/4,110)
        self.assertAlmostEqual(sum(v[1] for v in corners)/4,230)
        self.assertFalse(model.contains([119,238],[100,200],[120,260],30))
        self.assertTrue(model.contains([119,222],[100,200],[120,260],30))

    def test_zero_and_negative_yaw_and_inside_outside_are_not_axis_aligned_bounds(self):
        self.assertEqual(model.vertices([1,2],[10,20],0),[[1.,2.],[10.,2.],[10.,20.],[1.,20.]])
        self.assertTrue(model.contains([130,230],[100,200],[120,260],90))
        self.assertFalse(model.contains([110,250],[100,200],[120,260],90))
        self.assertTrue(model.contains([119,238],[100,200],[120,260],-30))

    def test_strict_coordinates_invalid_extents_and_nonfinite_yaw(self):
        self.assertEqual(model.vector('x=1e2, y=-.5'),[100.,-.5])
        for text in ['x=2garbage,y=3','x=nan,y=2','x=1e309,y=2']:
            self.assertIsNone(model.vector(text))
        for low,high,yaw in [([10,0],[1,2],0),([0,0],[1,2],float('nan'))]:
            with self.assertRaises(ValueError):model.vertices(low,high,yaw)
        self.assertNotEqual(model.angle(90),90*model.math.pi/180)

if __name__=='__main__':unittest.main()
