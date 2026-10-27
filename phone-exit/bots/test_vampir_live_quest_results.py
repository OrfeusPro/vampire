"""Current1811 observer: native codec parity and isolated synthetic sessions."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest
from urllib.request import urlopen
sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.quest_update_result import decode_quest_update_result
from vampir_core.quest_record import CURRENT_SOURCE_SHA256
from vampir_core.live_session import LiveSession,LiveSessions
from vampir_core.live_session_server import LiveSessionServer
from test_vampir_environment import owner
from test_vampir_live_quests import body as quest_body

WIRE=struct.Struct('<IQBBQQ')
def body(key=110120,code=0,index=0):return WIRE.pack(code,key,2,index,2**64-1,2**63+1)

class LiveQuestResultTests(unittest.TestCase):
    def session(self,bot='result',source=CURRENT_SOURCE_SHA256):
        s=LiveSession(bot_id=bot);s.bind_source(source);s.publish(owner());self.addCleanup(s.close);return s
    def receive(self,s,raw,**context):s.packet(1811,raw,**dict(dict(character_key=42,world_id=10010),**context))
    def test_native_900_case_parity_short_wrong_source_and_type(self):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('result_parity',root/'replay-quest-update-result-11316.py')
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);_,r=m.run()
        for c in r['cases']:
            v=decode_quest_update_result(WIRE.pack(*c['input']),source_sha256=CURRENT_SOURCE_SHA256)
            self.assertEqual([v.result_code,v.quest_id,v.state,v.progress.raw08,v.progress.raw10,v.progress.raw18],c['decoded'])
        for raw in [body()[:i] for i in range(30)]+[body()+b'x',bytearray(body()),None]:
            with self.assertRaises(ValueError):decode_quest_update_result(raw,source_sha256=CURRENT_SOURCE_SHA256)
        with self.assertRaises(ValueError):decode_quest_update_result(body(),source_sha256='0'*64)
    def test_fifty_sessions_http_precision_and_journal(self):
        sessions=[self.session('reply'+str(i)) for i in range(50)]
        for i,s in enumerate(sessions):self.receive(s,body(key=2**64-1-i,code=i,index=i))
        self.assertEqual([s.snapshot()['quest_update_result']['result_code'] for s in sessions],list(range(50)))
        row=sessions[0].snapshot()['quest_update_result']
        self.assertEqual(row['quest_id'],str(2**64-1));self.assertEqual(row['progress']['raw10'],str(2**64-1))
        self.assertFalse(row['action_confirmed']);self.assertFalse(row['applied_to_local_task'])
        copy=sessions[0].snapshot();copy['quest_update_result']['progress']['raw08']=999
        self.assertEqual(sessions[0].snapshot()['quest_update_result']['progress']['raw08'],0)
        registry=LiveSessions(capacity=50)
        for s in sessions:registry.attach(s)
        with LiveSessionServer(registry,port=0) as api:
            for i in (0,49):
                with urlopen(f'http://127.0.0.1:{api.server.server_port}/bots/reply{i}/state',timeout=3) as response:r=json.load(response)
                self.assertEqual(r['bot_id'],'reply'+str(i));self.assertEqual(r['quest_update_result']['result_code'],i)
                events=[e for e in r['journal'] if e['kind']=='quest_update_result_received']
                self.assertEqual(events[-1]['result_code'],i)
                self.assertNotIn('body',events[-1])
    def test_scope_source_decode_failure_world_clear_and_close(self):
        s=self.session();self.assertEqual(s.snapshot()['coverage']['quest_result'],'not_received')
        for context in ({'character_key':43},{'world_id':10012},{'character_key':None},{'character_key':True}):
            self.receive(s,body(),**context);self.assertIsNone(s.snapshot()['quest_update_result'])
        self.receive(s,body());self.assertIsNotNone(s.snapshot()['quest_update_result'])
        self.receive(s,b'broken');r=s.snapshot();self.assertIsNone(r['quest_update_result']);self.assertEqual(r['quest_result_decode_errors'],1)
        self.assertEqual(r['coverage']['quest_result'],'decode_error')
        self.receive(s,body());s.publish(owner(10012));self.assertIsNone(s.snapshot()['quest_update_result'])
        self.assertEqual(s.snapshot()['coverage']['quest_result'],'not_received')
        self.receive(s,body(),world_id=10012);s.close();self.assertIsNone(s.snapshot()['quest_update_result'])
        self.receive(s,body(),world_id=10012);self.assertIsNone(s.snapshot()['quest_update_result'])
        other=self.session('unknown','0'*64);self.receive(other,body());self.assertIsNone(other.snapshot()['quest_update_result'])
        self.assertEqual(other.snapshot()['coverage']['quest_result'],'not_verified')
    def test_result_neither_mutates_1854_nor_confirms_sent_action(self):
        s=self.session();s.packet(1854,quest_body(key=110120,progress=7),character_key=42,world_id=10010)
        before=s.snapshot()['quests'];key=object();s.install_actions(key,contracts={'quest_follow':'a'*64})
        offer=dict(kind='quest_follow',context='b'*64,arguments={'quest_id':'110120'});s.offer_actions(key,[offer])
        s.enqueue_action(dict(request_id='c'*32,**offer,policy=dict(skip_dialogues=True,auto_quests=False),origin='manual'))
        s.claim_action(key,context='b'*64);s.action_sent(key,'c'*32)
        for code in (0,10,0x1197):self.receive(s,body(code=code))
        self.assertEqual(s.snapshot()['quests'],before)
        self.assertEqual(s.snapshot()['action_queue']['records'][0]['status'],'sent')
        self.assertFalse(s.snapshot()['quest_update_result']['action_confirmed'])

if __name__=='__main__':unittest.main()
