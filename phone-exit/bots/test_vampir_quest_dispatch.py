"""Synthetic action admission: loopback HTTP -> owner -> local game socket."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.live_session import LiveSession,LiveSessions
from vampir_core.live_session_server import LiveSessionServer
from vampir_core.game_connection import GameConnection
from vampir_core.quest_update import QuestUpdate,encode_quest_update
from vampir_core.world_move_start import CURRENT_PROBE_SOURCE
from vampir_core.ping import PingPayload
from vampir_core.action_queue import SessionActionQueue
import test_vampir_quest_connection as wire
import test_vampir_action_api as api

CONTEXT='b'*64
POLICY=dict(skip_dialogues=True,auto_quests=False)
OFFER=dict(kind='quest_follow',context=CONTEXT,arguments={'quest_id':'110120'})
VALUE=QuestUpdate((1,2,3),0,110120,0)

class QuestDispatchTests(unittest.TestCase):
    connect=wire.QuestConnectionTests.connect
    packet=wire.QuestConnectionTests.packet
    ready=wire.QuestConnectionTests.ready
    read_request=wire.QuestConnectionTests.read_request
    request=api.ActionApiTests.request
    post=api.ActionApiTests.post
    token=api.ActionApiTests.token
    def prepare(self,index=0,bind=True):
        connection,server,client=self.ready()
        session=LiveSession(bot_id='dispatch'+str(index));session.bind_source(CURRENT_PROBE_SOURCE);session.publish(connection)
        self.addCleanup(session.close)
        key=object();session.install_actions(key,contracts={'quest_follow':'a'*64},connection=connection if bind else None)
        session.offer_actions(key,[OFFER])
        return session,key,connection,server
    def intent(self,index=1):
        return dict(request_id=f'{index:032x}',**OFFER,policy=POLICY.copy(),origin='manual')
    def claim(self,session,key):
        session.enqueue_action(self.intent());self.assertIsNotNone(session.claim_action(key,context=CONTEXT))
    def dispatch(self,session,key,**changes):
        return session.dispatch_quest_action(key,'0'*31+'1',context=changes.pop('context',CONTEXT),payload=changes.pop('payload',VALUE),**changes)
    def test_http_intent_owner_dispatch_wire_and_duplicate_without_confirmation(self):
        session,key,connection,peer=self.prepare();registry=LiveSessions(capacity=1);registry.attach(session)
        with LiveSessionServer(registry,port=0) as server:
            token=self.token(server,session)
            status,row=self.post(server,session,token,'actions',self.intent())
            self.assertEqual((status,row['status']),(202,'queued'))
            self.assertEqual(connection.queued_bytes,0)
            self.assertIsNotNone(session.claim_action(key,context=CONTEXT))
            self.assertEqual(self.dispatch(session,key)['status'],'sent')
            queued=connection.queued_bytes
            self.assertEqual(self.dispatch(session,key)['status'],'sent');self.assertEqual(connection.queued_bytes,queued)
            self.assertEqual(self.post(server,session,token,'actions',self.intent())[1]['status'],'sent')
            connection.pump(now=7,budget=wire.BUDGET)
            self.assertEqual(self.read_request(peer,7),(1810,4,encode_quest_update(VALUE,source_sha256=CURRENT_PROBE_SOURCE)))
            self.assertEqual(session.snapshot()['action_queue']['records'][0]['status'],'sent')
            # Explicit synthetic owner result; local socket receipt alone did not confirm.
            session.resolve_action(key,'0'*31+'1',status='confirmed')
            self.assertEqual(self.dispatch(session,key)['status'],'confirmed')
            self.assertEqual(connection.queued_bytes,0)
    def test_world_context_payload_and_foreign_owner_fences(self):
        for mode in ('unbound','world','connection_world','offers','closed_connection','context','quest','nan','foreign'):
            session,key,connection,peer=self.prepare(bind=mode!='unbound');self.claim(session,key)
            if mode=='world':
                connection.world_entry.target_position=replace(connection.world_entry.target_position,world_id=10011)
                session.publish(connection)
            if mode=='connection_world':connection.world_entry.target_position=replace(connection.world_entry.target_position,world_id=10011)
            if mode=='offers':session.offer_actions(key,[])
            if mode=='closed_connection':connection.close()
            options={'context':'c'*64} if mode=='context' else {'payload':QuestUpdate((1,2,3),0,110121,0)} if mode=='quest' else {'payload':QuestUpdate((float('nan'),2,3),0,110120,0)} if mode=='nan' else {}
            if mode=='foreign':
                with self.assertRaises(RuntimeError):self.dispatch(session,object())
            else:self.assertEqual(self.dispatch(session,key,**options)['status'],'failed')
            self.assertEqual(connection.queued_bytes,0)
    def test_known_backpressure_and_uncertain_enqueue_do_not_retry(self):
        session,key,connection,peer=self.prepare();self.claim(session,key)
        for i in range(8):connection.queue_ping(PingPayload(i,i))
        queued=connection.queued_bytes
        self.assertEqual(self.dispatch(session,key)['status'],'failed');self.assertEqual(connection.queued_bytes,queued)
        self.assertFalse(session.snapshot()['action_queue']['blocked'])
        session,key,connection,peer=self.prepare(1);self.claim(session,key)
        original=GameConnection.queue_quest_update
        def uncertain(conn,*args,**kwargs):
            original(conn,*args,**kwargs);raise OSError('synthetic uncertainty after append')
        with patch.object(GameConnection,'queue_quest_update',uncertain):
            self.assertEqual(self.dispatch(session,key)['status'],'unknown')
            queued=connection.queued_bytes
            self.assertEqual(self.dispatch(session,key)['status'],'unknown');self.assertEqual(connection.queued_bytes,queued)
        self.assertTrue(session.snapshot()['action_queue']['blocked'])
        self.assertNotIn('synthetic uncertainty',str(session.snapshot()))
    def test_two_bound_connections_keep_intents_and_outbound_separate(self):
        first,k1,c1,p1=self.prepare(1);second,k2,c2,p2=self.prepare(2)
        self.claim(first,k1);self.claim(second,k2)
        with self.assertRaises(RuntimeError):self.dispatch(first,k2)
        self.assertEqual(self.dispatch(first,k1)['status'],'sent');self.assertEqual(c2.queued_bytes,0)
        c1.pump(now=7,budget=wire.BUDGET);self.assertEqual(self.read_request(p1,7)[:2],(1810,4))
        self.assertEqual(self.dispatch(second,k2)['status'],'sent')
        c2.pump(now=7,budget=wire.BUDGET);self.assertEqual(self.read_request(p2,7)[:2],(1810,4))
    def test_expired_claim_and_session_close_never_append(self):
        now=[0];key=object();queue=SessionActionQueue(bot_id='expire',session_id='0'*32,source_sha256=CURRENT_PROBE_SOURCE,
            owner_key=key,contracts={'quest_follow':'a'*64},clock=lambda:now[0])
        queue.enqueue(bot_id='expire',session_id='0'*32,**self.intent());queue.claim(key,context=CONTEXT)
        now[0]=11;calls=[]
        self.assertEqual(queue.queue_claimed(key,'0'*31+'1',context=CONTEXT,enqueue=calls.append)['status'],'unknown')
        self.assertEqual(calls,[])
        session,key,connection,peer=self.prepare();self.claim(session,key);session.close()
        with self.assertRaises(RuntimeError):self.dispatch(session,key)
        self.assertEqual(connection.queued_bytes,0)

if __name__=='__main__':unittest.main()
