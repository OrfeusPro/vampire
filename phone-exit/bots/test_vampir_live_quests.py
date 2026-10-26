"""Synthetic isolated quest owners and HTTP boundary; no game IO."""
import json
from pathlib import Path
import struct
import sys
import unittest
from urllib.request import urlopen

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.live_session import LiveSession, LiveSessions
from vampir_core.live_session_server import LiveSessionServer
from vampir_core.quest_record import CURRENT_SOURCE_SHA256
from test_vampir_environment import owner


def body(key=2**64-1, progress=0, count=1):
    return struct.pack('<HBH',1,1,count)+struct.pack('<QBBQQBIII',key,2,3,progress,2**64-1,0,4,5,6)*count+bytes(8)


class LiveQuestTests(unittest.TestCase):
    def session(self,bot='fixture'):
        s=LiveSession(bot_id=bot);s.bind_source(CURRENT_SOURCE_SHA256);s.publish(owner())
        self.addCleanup(s.close)
        return s

    def receive(self,s,value,**context):
        s.packet(1854,value,**dict(dict(character_key=42,world_id=10010),**context))

    def test_fifty_owners_precision_copy_and_close(self):
        sessions=[self.session('quest-'+str(i)) for i in range(50)]
        for i,s in enumerate(sessions):self.receive(s,body(progress=i))
        self.assertEqual([s.snapshot()['quests'][0]['progress']['raw10'] for s in sessions],list(map(str,range(50))))
        snapshot=sessions[0].snapshot();snapshot['quests'][0]['progress']['raw10']='changed'
        self.assertEqual(sessions[0].snapshot()['quests'][0]['progress']['raw10'],'0')
        self.assertEqual(snapshot['quests'][0]['id'],str(2**64-1))
        self.assertIsNone(snapshot['quests'][0]['title'])
        sessions[0].close();self.assertEqual(sessions[0].snapshot()['quests'],[])
        self.assertEqual(sessions[1].snapshot()['character']['hp'],2700)
        self.assertEqual(sessions[1].snapshot()['quests'][0]['progress']['raw10'],'1')

    def test_unknown_empty_error_world_identity_and_source(self):
        s=self.session();self.assertEqual(s.snapshot()['coverage']['quests'],'not_received')
        self.receive(s,body(),character_key=None);self.assertEqual(s.snapshot()['quests'],[])
        self.receive(s,body(),character_key=43);self.assertEqual(s.snapshot()['quests'],[])
        self.receive(s,body());self.assertEqual(len(s.snapshot()['quests']),1)
        s.publish(owner(10012));self.assertEqual(s.snapshot()['coverage']['quests'],'not_received')
        self.receive(s,bytes(10),world_id=10012)
        self.assertEqual(s.snapshot()['coverage']['quests'],'last_received_message')
        self.assertEqual(s.snapshot()['quests'],[])
        self.receive(s,b'bad',world_id=10012)
        self.assertEqual(s.snapshot()['coverage']['quests'],'decode_error')
        self.assertIsNone(s.snapshot()['quest_snapshot'])
        unknown=LiveSession(bot_id='unknown');unknown.bind_source('0'*64);self.addCleanup(unknown.close)
        self.receive(unknown,body());self.assertEqual(unknown.snapshot()['coverage']['quests'],'not_verified')

    def test_full_message_budget_and_http_isolation(self):
        s=self.session('large');self.receive(s,body(count=127))
        self.assertEqual(len(s.snapshot()['quests']),127)
        other=self.session('other');self.receive(other,body(key=9,progress=55))
        registry=LiveSessions();registry.attach(s);registry.attach(other)
        with LiveSessionServer(registry,port=0) as api:
            # The actual loopback handler must deliver the complete bounded JSON.
            port=api.server.server_port
            with urlopen(f'http://127.0.0.1:{port}/bots/large/state') as response:large=json.load(response)
            with urlopen(f'http://127.0.0.1:{port}/bots/other/state') as response:small=json.load(response)
        self.assertEqual(len(large['quests']),127);self.assertEqual(small['quests'][0]['id'],'9')
        self.assertLess(len(json.dumps(large).encode()),262144)
        self.receive(s,body(count=128));self.assertEqual(s.snapshot()['coverage']['quests'],'decode_error')
        self.assertEqual(s.snapshot()['quests'],[])


if __name__=='__main__':unittest.main()
