"""Read-only loopback feed, lifecycle and private data cleanup."""
import json
from pathlib import Path
import struct
import sys
import unittest
from urllib.request import Request,urlopen
from urllib.error import HTTPError

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.map_position import MapProjection
from vampir_core.map_session import MapSession,MapSessionServer
from vampir_core.world_entry_flow import ServerTargetPosition
from vampir_core.character_select_result import WireVector3
from vampir_core.world_move_start import SOURCE_SHA256


class MapSessionTests(unittest.TestCase):
    def session(self):
        return MapSession(MapProjection(dict(source_sha256=SOURCE_SHA256,worlds={'1001':'10'},
            size=[10240,10240],center=[0,0],ground_distance=615000),source_sha256=SOURCE_SHA256))

    def test_snapshot_projection_unsupported_world_and_cleanup(self):
        s=self.session();vector=WireVector3(struct.unpack('<III',struct.pack('<fff',123,456,789)))
        self.assertEqual(s.snapshot()['state'],'waiting')
        s.update(ServerTargetPosition(1001,vector))
        state=s.snapshot();self.assertEqual(state['position']['x'],123)
        state['position']['x']=999;self.assertEqual(s.snapshot()['position']['x'],123)
        s.update(ServerTargetPosition(999,vector));self.assertEqual(s.snapshot()['state'],'unsupported_world')
        s.disconnect();self.assertIsNone(s.snapshot()['position'])

    def test_loopback_only_cors_no_commands_and_owner_cleanup(self):
        s=self.session()
        with MapSessionServer(s,port=0) as server:
            url='http://127.0.0.1:'+str(server.server.server_port)
            with urlopen(Request(url+'/state',headers={'Origin':'http://127.0.0.1:17946'}),timeout=2) as response:
                self.assertEqual(response.headers['Access-Control-Allow-Origin'],'http://127.0.0.1:17946')
                self.assertEqual(response.headers['Cache-Control'],'no-store')
                self.assertEqual(json.load(response)['state'],'waiting')
            for path,headers,method,expected in (('/state',{'Origin':'https://example.com'},'GET',403),
                    ('/state',{'Host':'evil.example'},'GET',403),('/command',{},'GET',404),('/state',{},'POST',501)):
                with self.assertRaises(HTTPError) as error:urlopen(Request(url+path,headers=headers,method=method),timeout=2)
                self.assertEqual(error.exception.code,expected)
                error.exception.close()
        self.assertFalse(server.thread.is_alive());self.assertEqual(s.snapshot()['state'],'disconnected')


if __name__=='__main__':unittest.main()
