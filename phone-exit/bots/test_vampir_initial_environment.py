"""ID301 integration through per-session state/API; all game data synthetic."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.environment import ObservedEnvironment,SOURCE_SHA256
from vampir_core.live_session import LiveSession
from vampir_core.live_session_server import LiveSessionServer
from test_vampir_environment import create,leave,owner


def player(key=84,*,hp=20,maximum=100,mp=30,max_mp=40,level=2,name='Игрок 🦇',xyz=(1.,2.,3.),stats=None):
    text=name.encode('utf-8')
    values=stats if stats is not None else [(3,level),(4,hp),(5,maximum),(9,mp),(10,max_mp)]
    return (struct.pack('<QQIH',key,0,0,len(text))+text+bytes(13)+bytes(16)+struct.pack('<HfffB',0,*xyz,0)
        +struct.pack('<H',len(values))+b''.join(struct.pack('<IQ',k,v) for k,v in values)
        +bytes(13)+bytes(40)+bytes(6))


def sight(npcs=(),players=()):
    return (struct.pack('<H',len(players))+b''.join(players)+struct.pack('<H',len(npcs))
        +b''.join(body[1:] for body in npcs)+bytes(8))


class InitialEnvironmentTests(unittest.TestCase):
    def test_current_id_handler_field_and_pc_class_bindings(self):
        path=Path(__file__).parent/'resource-tools/vampir/inspect-sight-bindings-11316.py'
        spec=importlib.util.spec_from_file_location('sight_bindings_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        report=json.loads(module.run().read_text('utf-8'))
        self.assertEqual(report['packet_id'],301);self.assertEqual(report['actor_class'],'NnCharacterPC')
        self.assertEqual(report['npc_initializer'],'0x145d74330');self.assertFalse(report['network_used'])

    def test_batch_upserts_distinct_kinds_self_filter_leave_and_empty_is_partial(self):
        e=ObservedEnvironment()
        def receive(body,key=42):return e.receive(301,body,source_sha256=SOURCE_SHA256,world_id=10010,character_key=key)
        receive(sight([create(84,hp=7)],[player(84,hp=8),player(42,hp=999)]))
        self.assertEqual(len(e.entities),2);self.assertEqual(e.entities['84']['hp'],7)
        self.assertEqual(e.entities['player:84']['hp'],8);self.assertEqual(e.entities['player:84']['mp'],30)
        self.assertEqual(e.entities['player:84']['level'],2);self.assertNotIn('player:42',e.entities)
        revision=e.revision;receive(sight(players=[player(85),player(84,hp=9)]))
        self.assertEqual(e.revision,revision+1);self.assertEqual(len(e.entities),3);self.assertEqual(e.entities['player:84']['hp'],9)
        receive(sight());self.assertEqual(len(e.entities),3)
        e.receive(302,leave(visible=[(84,84,84)]),source_sha256=SOURCE_SHA256,world_id=10010)
        self.assertEqual(len(e.entities),3)
        e.receive(302,leave([84,85]),source_sha256=SOURCE_SHA256,world_id=10010)
        self.assertFalse(e.entities);self.assertEqual(e.coverage,'partial');self.assertFalse(e.snapshot()['summary']['complete'])
        e.world(10012);self.assertFalse(e.snapshot()['summary']['sight_received']);self.assertFalse(e.players_received)

    def test_unknown_own_key_precision_name_bounds_duplicates_atomic_error_and_capacity(self):
        e=ObservedEnvironment(max_entities=2)
        def receive(body,key=42,world=10010):return e.receive(301,body,source_sha256=SOURCE_SHA256,world_id=world,character_key=key)
        receive(sight([create(1)],[player(84)]),None)
        self.assertNotIn('player:84',e.entities);self.assertFalse(e.players_received);self.assertEqual(e.skipped_players,1)
        receive(sight(players=[player(84,name='😀'*100,xyz=(float('nan'),0.,1.),stats=[(4,2**64-1),(4,12),(9,2**64-1),(3,3)])]))
        row=e.entities['player:84'];self.assertEqual(row['hp'],12);self.assertIsNone(row['mp']);self.assertIsNone(row['position'])
        self.assertEqual(row['name'],'😀'*32);self.assertTrue(row['name_truncated']);self.assertFalse(row['stats_current'])
        event=receive(sight([create(2)],[player(84,hp=13)]));self.assertEqual(event,'environment_limit_reached')
        self.assertEqual(len(e.entities),2);self.assertEqual(e.entities['player:84']['hp'],13)
        snapshot=e.snapshot();snapshot['entities'][0]['hp']=999;snapshot['summary']['other_records']['gadgets']=999
        self.assertNotEqual(e.entities['1']['hp'],999);self.assertEqual(e.other_records['gadgets'],0)
        receive(sight([create(3)],[player(85)])[:-1]);self.assertFalse(e.entities);self.assertEqual(e.coverage,'decode_error')
        self.assertFalse(e.players_received);self.assertFalse(e.sight_received)
        receive(sight([create(3)],[player(85)]),world=None);self.assertFalse(e.entities)
        with self.assertRaises(ValueError):e.receive(301,sight(),source_sha256='old',world_id=10010)

    def test_fifty_owners_initial_batches_keep_accounts_worlds_vitals_and_snapshots_separate(self):
        sessions=[LiveSession(bot_id='sight-fixture-'+str(i)) for i in range(50)]
        try:
            for i,s in enumerate(sessions):
                s.bind_source(SOURCE_SHA256);s.publish(owner())
                s.packet(301,sight([create(84,hp=i)],[player(85,hp=100+i,mp=200+i,name='Fixture '+str(i)),player(42,hp=999)]),world_id=10010,character_key=42)
                value=s.snapshot();self.assertEqual(value['character']['hp'],2700);self.assertEqual(value['character']['mp'],2000)
                self.assertEqual([row['hp'] for row in value['entities']],[i,100+i]);self.assertTrue(value['environment']['players_received'])
                self.assertEqual(value['coverage']['entities'],'partial')
            sessions[0].packet(302,leave([85]),world_id=10010);self.assertEqual(len(sessions[0].snapshot()['entities']),1)
            self.assertEqual(sessions[1].snapshot()['entities'][1]['hp'],101)
            sessions[1].publish(owner(10012));self.assertFalse(sessions[1].snapshot()['entities'])
            sessions[2].close();sessions[2].packet(301,sight([create(99)]),world_id=10010,character_key=42)
            self.assertFalse(sessions[2].snapshot()['entities'])
            sessions[3].packet(301,b'bad',world_id=10010,character_key=42)
            self.assertFalse(sessions[3].snapshot()['entities']);self.assertEqual(sessions[3].snapshot()['character']['hp'],2700)
        finally:
            for s in sessions:s.close()

    def test_maximum_player_names_stats_and_both_http_pages_stay_bounded(self):
        from http.client import HTTPConnection
        s=LiveSession(bot_id='sight-max-fixture');s.bind_source(SOURCE_SHA256);s.publish(owner(0xffffffff))
        try:
            maximum=2**53-1
            for start in range(0,512,64):
                batch=[player(2**64-1-i,name='😀'*100,hp=maximum,maximum=maximum,mp=maximum,max_mp=maximum,level=maximum,xyz=(3.4028234663852886e38,)*3) for i in range(start,start+64)]
                s.packet(301,sight(players=batch),world_id=0xffffffff,character_key=42)
            self.assertEqual(len(s.snapshot()['entities']),512)
            for i in range(5):
                values=[(j,0,2**63-1) for j in range(i*207,(i+1)*207)]
                s.packet(322,struct.pack('<QH',42,len(values))+b''.join(struct.pack('<iQQ',*v) for v in values)+bytes(3),character_key=42,world_id=0xffffffff)
            keys=set()
            with LiveSessionServer(s,port=0) as server:
                # Exercise separate connections repeatedly, including each tail.
                for page in (0,1)*3:
                    connection=HTTPConnection('127.0.0.1',server.server.server_port,timeout=3)
                    try:
                        connection.request('GET','/bots/sight-max-fixture/state?entity_page='+str(page))
                        response=connection.getresponse();self.assertEqual(response.status,200)
                        body=response.read(262145)
                        self.assertEqual(len(body),int(response.getheader('Content-Length')))
                    finally:connection.close()
                    self.assertLess(len(body),262144);value=json.loads(body)
                    self.assertEqual(value['environment']['known_count'],512);self.assertEqual(len(value['entities']),256)
                    keys.update(row['key'] for row in value['entities'])
                    self.assertTrue(all(len(row['name'])==32 and row['name_truncated'] for row in value['entities']))
                self.assertEqual(len(keys),512)
        finally:s.close()


if __name__=='__main__':unittest.main()
