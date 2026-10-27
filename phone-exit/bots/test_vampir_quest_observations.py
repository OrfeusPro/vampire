"""Post-send quest observations are scoped candidates, never action confirmation."""
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
import vampir_core.live_session as live
import test_vampir_quest_dispatch as dispatch_fixture
import test_vampir_quest_connection as wire
from test_vampir_live_quest_results import body as result_body

def sync(index=0,key=110120,count=1):
    return struct.pack('<HBH',1,0,count)+struct.pack('<QBBQQBIII',key,2,index,0,0,0,0,0,0)*count+bytes(8)

class QuestObservationsTests(unittest.TestCase):
    connect=wire.QuestConnectionTests.connect
    packet=wire.QuestConnectionTests.packet
    ready=wire.QuestConnectionTests.ready
    read_request=wire.QuestConnectionTests.read_request
    prepare=dispatch_fixture.QuestDispatchTests.prepare
    intent=dispatch_fixture.QuestDispatchTests.intent
    claim=dispatch_fixture.QuestDispatchTests.claim
    dispatch=dispatch_fixture.QuestDispatchTests.dispatch
    def receive(self,s,packet_id,body,**changes):
        c=s.snapshot()['character'];context=dict(character_key=int(c['key']),world_id=c['world_id']);context.update(changes)
        s.packet(packet_id,body,**context)
    def start(self,index=0):
        s,k,c,p=self.prepare(index);self.receive(s,1854,sync());self.claim(s,k);self.dispatch(s,k);return s,k,c,p
    def flush(self,c,p):c.pump(now=7,budget=wire.BUDGET);self.read_request(p,7)
    def test_before_send_is_excluded_baseline_frozen_at_socket_acceptance(self):
        s,k,c,p=self.start();self.receive(s,1811,result_body())
        self.receive(s,1854,sync(1))
        self.assertEqual(s.snapshot()['quest_transport']['observations']['reply'],None)
        self.flush(c,p)
        self.receive(s,1854,sync(1))
        receipt=s.snapshot()['quest_transport'];self.assertEqual(receipt['progress_baseline']['progress']['raw08'],1)
        self.assertFalse(receipt['observations']['progress']['changed'])
        self.receive(s,1854,sync(2));self.receive(s,1811,result_body(index=2))
        receipt=s.snapshot()['quest_transport'];self.assertTrue(receipt['observations']['progress']['changed'])
        self.assertFalse(receipt['observations']['reply']['index_matches_sent'])
        self.assertFalse(receipt['server_confirmed']);self.assertEqual(receipt['observations']['causality'],'not_proven')
        self.assertEqual(s.snapshot()['action_queue']['records'][0]['status'],'sent')
    def test_local_response_packet_records_candidate_and_duplicate_no_event(self):
        s,k,c,p=self.start();self.flush(c,p)
        character=s.snapshot()['character']
        c._on_packet=lambda packet:s.packet(packet.packet_id,packet.body,character_key=int(character['key']),world_id=character['world_id'])
        # Actual receive stream decodes the synthetic server frame before observer.
        self.packet(c,p,c._socket,1811,result_body(),8)
        receipt=s.snapshot()['quest_transport'];self.assertEqual(receipt['observations']['reply']['result_code'],0)
        self.assertTrue(receipt['observations']['reply']['index_matches_sent'])
        self.assertEqual(s.snapshot()['quest_update_result']['candidate_request_id'],receipt['request_id'])
        self.receive(s,1811,result_body())
        events=[e for e in s.snapshot()['journal'] if e['kind']=='quest_reply_candidate'];self.assertEqual(len(events),1)
        snapshot=s.snapshot();snapshot['quest_transport']['observations']['reply']['result_code']=99
        self.assertEqual(s.snapshot()['quest_transport']['observations']['reply']['result_code'],0)
        for code in (10,0x1197):self.receive(s,1811,result_body(code=code))
        self.assertEqual(s.snapshot()['quest_transport']['observations']['reply']['result_code'],0x1197)
        self.assertEqual(s.snapshot()['action_queue']['records'][0]['status'],'sent')
    def test_other_quest_scope_duplicate_rows_and_window_expiry(self):
        s,k,c,p=self.start();self.flush(c,p)
        self.receive(s,1811,result_body(key=110121));self.assertIsNone(s.snapshot()['quest_transport']['observations']['reply'])
        before=s.snapshot()['quests']
        self.receive(s,1854,sync(5),world_id=999)
        self.assertEqual(s.snapshot()['quests'],before)
        self.receive(s,1811,result_body(),world_id=999);self.assertIsNone(s.snapshot()['quest_transport']['observations']['reply'])
        self.receive(s,1854,sync(1,count=2));o=s.snapshot()['quest_transport']['observations']['progress']
        self.assertEqual(o['matches'],2);self.assertFalse(o['changed']);self.assertIsNone(o['current'])
        deadline=s._quest_transport['_deadline']
        with patch.object(live.time,'monotonic',return_value=deadline+1):
            self.receive(s,1811,result_body());self.receive(s,1854,sync(2))
        self.assertIsNone(s.snapshot()['quest_transport']['observations']['reply'])
        self.assertEqual(s.snapshot()['quest_transport']['observations']['progress']['matches'],2)
    def test_two_sessions_do_not_cross_and_world_change_rejects_old_context(self):
        a,ka,ca,pa=self.start(1);b,kb,cb,pb=self.start(2);self.flush(ca,pa);self.flush(cb,pb)
        self.receive(a,1811,result_body(code=10));self.receive(a,1854,sync(1))
        self.assertIsNone(b.snapshot()['quest_transport']['observations']['reply'])
        self.assertIsNone(b.snapshot()['quest_transport']['observations']['progress'])
        from dataclasses import replace
        ca.world_entry.target_position=replace(ca.world_entry.target_position,world_id=10012);a.publish(ca)
        self.receive(a,1811,result_body(),world_id=10010)
        self.receive(a,1854,sync(2),world_id=10010)
        self.assertEqual(a.snapshot()['quest_transport']['observations']['reply']['result_code'],10)
        self.assertEqual(a.snapshot()['quests'],[])
        self.receive(b,1811,result_body());self.assertEqual(b.snapshot()['quest_transport']['observations']['reply']['result_code'],0)
        for s in (a,b):self.assertFalse(s.snapshot()['quest_transport']['server_confirmed'])

if __name__=='__main__':unittest.main()
