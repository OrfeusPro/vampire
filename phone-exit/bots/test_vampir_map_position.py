"""Projection without account, network, atlas extraction or movement."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.character_select_result import WireVector3
from vampir_core.map_position import MapProjection
from vampir_core.world_entry_flow import ServerTargetPosition
from vampir_core.world_move_start import SOURCE_SHA256


class MapPositionTests(unittest.TestCase):
    def setUp(self):
        self.manifest=dict(source_sha256=SOURCE_SHA256,worlds={'1001':'10'},
            size=[10240,10240],center=[0,0],ground_distance=615000)
        self.projection=MapProjection(self.manifest,source_sha256=SOURCE_SHA256)

    def point(self,x,y,z=0,world=1001):
        vector=WireVector3(struct.unpack('<III',struct.pack('<fff',x,y,z)))
        return ServerTargetPosition(world,vector)

    def test_center_corners_axis_order_and_height(self):
        for x,y,expected in ((0,0,(5120,5120)),(-307500,-307500,(0,0)),
                (307500,307500,(10240,10240)),(307500,-307500,(10240,0))):
            p=self.projection.project(self.point(x,y,123))
            self.assertEqual((p.pixel_x,p.pixel_y),expected)
            self.assertEqual(p.z,123);self.assertTrue(p.inside)
            self.assertEqual(p.semantics,'server_target_before_engine_correction')

    def test_outside_is_preserved_not_clamped(self):
        p=self.projection.project(self.point(615000,0))
        self.assertFalse(p.inside);self.assertEqual(p.pixel_x,15360)

    def test_unknown_world_nonfinite_and_source_mismatch_fail(self):
        for point in (self.point(0,0,world=999),self.point(float('nan'),0)):
            with self.assertRaises(ValueError):self.projection.project(point)
        with self.assertRaises(ValueError):MapProjection(self.manifest,source_sha256='old')
        for change in ({'ground_distance':0},{'size':[0,10240]},{'center':[float('inf'),0]}):
            with self.assertRaises(ValueError):MapProjection(dict(self.manifest,**change),source_sha256=SOURCE_SHA256)


if __name__=='__main__':unittest.main()
