"""Per-session observed NPC subset; all packets and owners here are synthetic."""
import json
import importlib.util
from pathlib import Path
import struct
import sys
from types import SimpleNamespace as N
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.environment import SOURCE_SHA256,ObservedEnvironment
from vampir_core.live_session import LiveSession
from vampir_core.character_select_result import SelectionRecord


def create(key=42,hp=90,maximum=100,xyz=(1.,2.,3.)):
    return (b'\0'+struct.pack('<QIfffBQQQBIQH',key,123,*xyz,0,hp,maximum,0,0,0,0,0)
        +bytes(4)+struct.pack('<HQQIHQ',0,0,0,0,0,0)+bytes(3)+struct.pack('<fI',1.,0))


def leave(keys=(),visible=()):
    return struct.pack('<H',len(keys))+b''.join(struct.pack('<Q',k) for k in keys)+struct.pack('<H',len(visible))+b''.join(struct.pack('<QQQ',*row) for row in visible)+b'\0'


def owner(world=10010):
    stats=tuple(SelectionRecord(((8,k),(16,v))) for k,v in [(4,2700),(5,2700),(9,2000),(10,2000)])
    return N(world_entry=N(state='finish_response',target_position=N(world_id=world,vector=N(finite_values=lambda:(10.,20.,30.)))),
        selection=N(response=N(player=SelectionRecord(((8,42),(0x1c8,stats)))),characters=N(records=[N(u64=[42],strings=['Fixture'])])),heartbeat=None)


class EnvironmentTests(unittest.TestCase):
    def test_current_registration_and_npc_key_position_hp_source_anchors(self):
        path=Path(__file__).parent/'resource-tools/vampir/inspect-world-registrations-11316.py'
        spec=importlib.util.spec_from_file_location('world_registration_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        report,rows=module.run();self.assertEqual({r['packet'] for r in rows},{'PktNpcCreateNotify','PktSightLeaveNotify'})
        value=json.loads(report.read_text('utf-8'));self.assertFalse(value['network_used'])
        self.assertEqual(len(value['npc_field_anchors']),18)
    def test_create_replace_leave_and_quest_keys_do_not_remove_actors(self):
        e=ObservedEnvironment()
        def receive(packet,body):return e.receive(packet,body,source_sha256=SOURCE_SHA256,world_id=10010)
        receive(324,create());self.assertEqual(e.coverage,'partial');self.assertFalse(e.snapshot()['summary']['complete'])
        receive(324,create(hp=12));self.assertEqual(len(e.entities),1);self.assertEqual(e.entities['42']['hp'],12)
        receive(302,leave(visible=[(42,42,42)]));self.assertIn('42',e.entities)
        receive(302,leave([42,42,99]));self.assertFalse(e.entities);self.assertEqual(e.coverage,'partial')

    def test_world_decode_error_nonfinite_capacity_and_snapshot_ownership(self):
        e=ObservedEnvironment(max_entities=1)
        def receive(body,world=1):return e.receive(324,body,source_sha256=SOURCE_SHA256,world_id=world)
        receive(create());receive(create(key=43));self.assertEqual(len(e.entities),1);self.assertTrue(e.limited)
        receive(create(hp=0));self.assertEqual(e.entities['42']['hp'],0)
        snapshot=e.snapshot();snapshot['entities'][0]['hp']=999;self.assertEqual(e.entities['42']['hp'],0)
        receive(b'bad');self.assertFalse(e.entities);self.assertEqual(e.coverage,'decode_error')
        receive(create(hp=2**64-1,xyz=(float('nan'),1.,2.)),2)
        self.assertFalse(e.limited);self.assertIsNone(e.entities['42']['hp']);self.assertIsNone(e.entities['42']['position'])
        e.world(3);self.assertFalse(e.entities);self.assertEqual(e.coverage,'not_received')
        receive(create(),None);self.assertFalse(e.entities);self.assertEqual(e.world_id,3)
        with self.assertRaises(ValueError):e.receive(324,create(),source_sha256='old',world_id=3)
        with self.assertRaises(ValueError):e.world(True)

    def test_fifty_sessions_same_actor_key_remain_isolated_and_do_not_touch_main_vitals(self):
        sessions=[LiveSession(bot_id='fixture-'+str(i)) for i in range(50)]
        for i,s in enumerate(sessions):
            s.bind_source(SOURCE_SHA256);s.publish(owner());s.packet(324,create(hp=i),world_id=10010)
            self.assertEqual(s.snapshot()['character']['hp'],2700)
        self.assertEqual([s.snapshot()['entities'][0]['hp'] for s in sessions],list(range(50)))
        sessions[0].packet(302,leave([42]),world_id=10010)
        self.assertFalse(sessions[0].snapshot()['entities']);self.assertEqual(sessions[1].snapshot()['entities'][0]['hp'],1)
        sessions[1].publish(owner(10012));value=sessions[1].snapshot()
        self.assertFalse(value['entities']);self.assertEqual(value['character']['world_id'],10012);self.assertEqual(value['character']['hp'],2700)
        sessions[2].close();self.assertFalse(sessions[2].snapshot()['entities'])
        for s in sessions:s.close()

    def test_events_without_world_and_after_close_are_ignored_and_payload_stays_bounded(self):
        s=LiveSession(bot_id='fixture');s.bind_source(SOURCE_SHA256)
        s.packet(324,create());self.assertFalse(s.snapshot()['entities'])
        s.publish(owner())
        for key in range(513):s.packet(324,create(key=key),world_id=10010)
        value=s.snapshot();self.assertEqual(len(value['entities']),512);self.assertTrue(value['environment']['limit_reached'])
        self.assertEqual(len(s.snapshot(for_api=True)['entities']),256)
        s.publish(N(world_entry=N(state='waiting')));self.assertFalse(s.snapshot()['entities'])
        s.close();s.packet(324,create(),world_id=10010);self.assertFalse(s.snapshot()['entities'])

    def test_maximum_stats_and_npc_pages_stay_under_http_limit(self):
        from urllib.request import urlopen
        from urllib.error import HTTPError
        from vampir_core.live_session_server import LiveSessionServer
        s=LiveSession(bot_id='fixture');s.bind_source(SOURCE_SHA256);s.publish(owner(0xffffffff))
        for i in range(512):s.packet(324,create(key=2**64-1-i,hp=2**53-1,maximum=2**53-1,xyz=(3.4028234663852886e38,)*3),world_id=0xffffffff)
        for i in range(5):
            values=[(j,0,2**63-1) for j in range(i*207,(i+1)*207)]
            body=struct.pack('<QH',42,len(values))+b''.join(struct.pack('<iQQ',*v) for v in values)+bytes(3)
            s.packet(322,body,character_key=42,world_id=0xffffffff)
        self.assertEqual(len(s.snapshot()['entities']),512)
        keys=set()
        with LiveSessionServer(s,port=0) as server:
            base='http://127.0.0.1:'+str(server.server.server_port)+'/bots/fixture/state'
            for page in (0,1):
                with urlopen(base+'?entity_page='+str(page)) as response:body=response.read()
                self.assertLess(len(body),262144);value=json.loads(body)
                self.assertEqual(value['environment']['known_count'],512)
                self.assertEqual(value['environment']['entity_page'],page)
                self.assertEqual(len(value['entities']),256)
                keys.update(row['key'] for row in value['entities'])
            self.assertEqual(len(keys),512)
            for query in ('entity_page=2','entity_page=-1','entity_page=','entity_page=0&entity_page=1','other=1'):
                with self.assertRaises(HTTPError) as error:urlopen(base+'?'+query)
                self.assertEqual(error.exception.code,400)
                error.exception.close()
            s.packet(302,leave([int(k) for k in keys]),world_id=0xffffffff)
            self.assertEqual(s.snapshot(for_api=True,entity_page=1)['environment']['entity_page'],0)


if __name__=='__main__':unittest.main()
