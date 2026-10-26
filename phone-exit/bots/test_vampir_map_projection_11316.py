"""Source-bound existing projection reuse for 1.13.16; no game auth/network."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.map_position import MapProjection
from vampir_core.map_projection_input import load_projection
from vampir_core.live_session import LiveSession
from vampir_core.character_select_result import WireVector3
from vampir_core.world_entry_flow import ServerTargetPosition
from vampir_core.world_move_start import SOURCE_SHA256 as OLD,CURRENT_PROBE_SOURCE as SHA
from test_vampir_environment import owner
class Projection11316Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  path=Path(__file__).parent/'resource-tools/vampir/audit-map-projection-11316.py'
  spec=importlib.util.spec_from_file_location('current_map_audit_test',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  cls.path,cls.manifest=m.run()
 def point(self,x,y,z=-44,world=10012):
  return ServerTargetPosition(world,WireVector3(struct.unpack('<III',struct.pack('<fff',x,y,z))))
 def test_current_native_fields_exact_tables_and_real_world_target_projection(self):
  self.assertEqual(self.manifest['worlds']['10012'],'10');self.assertEqual(len(self.manifest['worlds']),36)
  p=load_projection(self.path,source_sha256=SHA).project(self.point(90049,151840))
  self.assertEqual((p.x,p.y,p.z),(90049.,151840.,-44.));self.assertTrue(p.inside)
  self.assertAlmostEqual(p.pixel_x,90049*10240/615000+5120)
  self.assertAlmostEqual(p.pixel_y,151840*10240/615000+5120)
  self.assertEqual(p.semantics,'server_target_before_engine_correction')
 def test_fifty_owners_share_only_projection_configuration(self):
  projection=MapProjection(self.manifest,source_sha256=SHA);sessions=[]
  try:
   for i in range(50):
    s=LiveSession(bot_id='map-fixture-'+str(i),projection=projection);sessions.append(s);s.bind_source(SHA)
    o=owner(10012);o.world_entry.target_position=self.point(i*100,151840)
    s.publish(o)
   for i,s in enumerate(sessions):
    snap=s.snapshot();self.assertEqual(snap['position']['x'],i*100);self.assertEqual(snap['character']['hp'],2700)
    snap['position']['x']=-1;self.assertEqual(s.snapshot()['position']['x'],i*100)
   sessions[0].close();self.assertIsNone(sessions[0].snapshot()['position']);self.assertEqual(sessions[1].snapshot()['position']['x'],100)
   o=owner(99999);o.world_entry.target_position=self.point(1,2,world=99999);sessions[1].publish(o)
   self.assertIsNone(sessions[1].snapshot()['position']);self.assertIsNotNone(sessions[2].snapshot()['position'])
  finally:
   for s in sessions:s.close()
 def test_source_guards_and_explicit_immutable_input(self):
  with self.assertRaises(ValueError):load_projection(self.path,source_sha256=OLD)
  s=LiveSession(bot_id='wrong-source',projection=MapProjection(self.manifest,source_sha256=SHA))
  try:
   with self.assertRaises(ValueError):s.bind_source(OLD)
  finally:s.close()
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder);archive=root/'fixture.pak';archive.write_bytes(b'fixture only')
   manifest=dict(self.manifest,installed_archive=dict(path=str(archive),sha256=hashlib.sha256(archive.read_bytes()).hexdigest()))
   raw=json.dumps(manifest).encode();p=root/hashlib.sha256(raw).hexdigest()/'manifest.json';p.parent.mkdir();p.write_bytes(raw)
   self.assertEqual(load_projection(p,source_sha256=SHA).project(self.point(0,0)).pixel_x,5120)
   archive.write_bytes(b'changed')
   with self.assertRaises(ValueError):load_projection(p,source_sha256=SHA)
   p.write_bytes(raw+b' ')
   with self.assertRaises(ValueError):load_projection(p,source_sha256=SHA)
if __name__=='__main__':unittest.main()
