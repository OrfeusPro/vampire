"""Explicit owner-selected step -> HTTP intent -> one pump dispatch, no retry."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.live_session import LiveSession,LiveSessions
from vampir_core.live_session_server import LiveSessionServer
from vampir_core.quest_update import QuestUpdate
import test_vampir_quest_connection as wire
import test_vampir_quest_dispatch as dispatch
import test_vampir_action_api as api
from test_vampir_quest_observations import sync

VALUE=QuestUpdate((1,2,3),0,110120,0)
class QuestOwnerPumpTests(unittest.TestCase):
    connect=wire.QuestConnectionTests.connect
    packet=wire.QuestConnectionTests.packet
    ready=wire.QuestConnectionTests.ready
    read_request=wire.QuestConnectionTests.read_request
    prepare=dispatch.QuestDispatchTests.prepare
    request=api.ActionApiTests.request
    post=api.ActionApiTests.post
    token=api.ActionApiTests.token
    def offered(self,index=0):
        s,k,c,p=self.prepare(index)
        person=s.snapshot()['character']
        s.packet(1854,sync(),character_key=int(person['key']),world_id=person['world_id'])
        offer=s.offer_quest_step(k,payload=VALUE)
        return s,k,c,p,offer
    def intent(self,offer,i=1):return dict(request_id=f'{i:032x}',**offer,policy=dict(skip_dialogues=True,auto_quests=True),origin='manual')
    def test_http_click_then_owner_loop_queues_exactly_once(self):
        s,k,c,p,offer=self.offered();registry=LiveSessions(capacity=1);registry.attach(s)
        self.assertIsNone(s.pump_quest_actions(c));self.assertEqual(c.queued_bytes,0)
        with LiveSessionServer(registry,port=0) as server:
            token=self.token(server,s)
            self.assertEqual(self.post(server,s,token,'actions',self.intent(offer))[0],202)
            row=s.pump_quest_actions(c);self.assertEqual(row['status'],'sent')
            self.assertIsNone(s.pump_quest_actions(c))
            c.pump(now=7,budget=wire.BUDGET);self.assertEqual(self.read_request(p,7)[:2],(1810,4))
            self.assertEqual(s.snapshot()['quest_transport']['status'],'socket_accepted')
            self.assertEqual(self.post(server,s,token,'actions',self.intent(offer))[1]['status'],'sent')
            self.assertEqual(self.post(server,s,token,'actions',self.intent(offer,2))[0],409)
            self.assertEqual(c.queued_bytes,0)
    def test_stale_step_rejected_before_enqueue_even_if_intent_queued(self):
        for mode in ('progress','duplicate','world','stop'):
            s,k,c,p,offer=self.offered();s.enqueue_action(self.intent(offer))
            person=s.snapshot()['character']
            if mode in ('progress','duplicate'):
                s.packet(1854,sync(1) if mode=='progress' else sync(count=2),character_key=int(person['key']),world_id=person['world_id'])
            if mode=='world':
                from dataclasses import replace
                c.world_entry.target_position=replace(c.world_entry.target_position,world_id=10012);s.publish(c)
            if mode=='stop':s.request_stop()
            self.assertIsNone(s.pump_quest_actions(c));self.assertEqual(c.queued_bytes,0)
            if mode!='stop':self.assertEqual(s.snapshot()['action_queue']['records'][0]['status'],'failed')
    def test_foreign_owner_connection_invalid_index_and_default_noop(self):
        s,k,c,p,offer=self.offered();other,ko,co,po,_=self.offered(1)
        with self.assertRaises(RuntimeError):s.offer_quest_step(ko,payload=VALUE)
        with self.assertRaises(RuntimeError):s.pump_quest_actions(co)
        with self.assertRaises(ValueError):s.offer_quest_step(k,payload=QuestUpdate((1,2,3),0,110120,1))
        read_only=LiveSession(bot_id='read-only');self.addCleanup(read_only.close)
        self.assertIsNone(read_only.pump_quest_actions(c));self.assertEqual(c.queued_bytes,0)
        self.assertEqual(co.queued_bytes,0)
    def test_changed_context_requires_new_explicit_offer_and_intent(self):
        s,k,c,p,offer=self.offered();s.enqueue_action(self.intent(offer))
        person=s.snapshot()['character'];s.packet(1854,sync(1),character_key=int(person['key']),world_id=person['world_id'])
        self.assertIsNone(s.pump_quest_actions(c))
        fresh=s.offer_quest_step(k,payload=QuestUpdate((1,2,3),0,110120,1));self.assertNotEqual(fresh['context'],offer['context'])
        self.assertIsNone(s.pump_quest_actions(c));self.assertEqual(c.queued_bytes,0)
        s.enqueue_action(self.intent(fresh,2));self.assertEqual(s.pump_quest_actions(c)['status'],'sent')
        self.assertIsNone(s.pump_quest_actions(c));c.pump(now=7,budget=wire.BUDGET)
        self.assertEqual(self.read_request(p,7)[:2],(1810,4))

if __name__=='__main__':unittest.main()
