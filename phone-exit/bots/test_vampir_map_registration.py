"""Image matching must reject unrelated or concentrated correspondences."""
import importlib.util
import unittest
from pathlib import Path
import numpy as np

spec=importlib.util.spec_from_file_location('vampir_registration',Path(__file__).parent/'resource-tools/vampir/register-map-screenshot.py')
registration=importlib.util.module_from_spec(spec);spec.loader.exec_module(registration)


class MapRegistrationTests(unittest.TestCase):
    def points(self):
        rng=np.random.default_rng(17)
        src=rng.uniform([90,80],[1200,690],(180,2)).astype(np.float32)
        dst=src*.75+[3022,3121]+rng.normal(0,.08,src.shape)
        return src,dst.astype(np.float32)

    def test_separate_spatial_cells_validate_known_shift_and_scale(self):
        src,dst=self.points();matrix,ok,stats=registration.fit_verified(src,dst)
        np.testing.assert_allclose(matrix[:,:2],np.eye(2)*.75,atol=.001)
        np.testing.assert_allclose(matrix[:,2],[3022,3121],atol=.1)
        self.assertLess(stats['validation_median_atlas_px'],1)
        self.assertGreater(stats['validation_matches'],40)

    def test_few_outliers_do_not_change_placement(self):
        src,dst=self.points();dst[:6]+=[400,-500]
        matrix,ok,stats=registration.fit_verified(src,dst)
        self.assertFalse(ok[:6].any())
        self.assertGreater(stats['validation_inlier_fraction'],.9)

    def test_unrelated_points_rejected(self):
        src,dst=self.points();dst=np.random.default_rng(2).uniform(0,5000,dst.shape).astype(np.float32)
        with self.assertRaises(ValueError):registration.fit_verified(src,dst)

    def test_clustered_points_cannot_validate_large_map_coverage(self):
        src,dst=self.points();src=src/30+[600,300];dst=src*.75+[3022,3121]
        with self.assertRaises(ValueError):registration.fit_verified(src.astype(np.float32),dst.astype(np.float32))

    def test_rotation_incompatible_with_historical_world_map_rejected(self):
        src,dst=self.points();angle=np.deg2rad(30);m=np.array([[np.cos(angle),-np.sin(angle)],[np.sin(angle),np.cos(angle)]])
        dst=(src@m.T+[3000,3000]).astype(np.float32)
        with self.assertRaises(ValueError):registration.fit_verified(src,dst)


if __name__=='__main__':unittest.main()
