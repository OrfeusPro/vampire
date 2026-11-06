"""Current observer and selection API integration; no real game operations."""
import json
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.live_session import LiveSession
from vampir_core.live_session_server import LiveSessionServer
from vampir_core.quest_sync import decode_quest_sync
from vampir_core.tutorial_update import decode_tutorial_update
from test_vampir_bounded_world import admitted, admission
from test_vampir_live_session import owner
from test_vampir_live_quests import body
import test_vampir_action_api as api


class QuestAutomationOwnerTests(unittest.TestCase):
    request=api.ActionApiTests.request
    post=api.ActionApiTests.post
    token=api.ActionApiTests.token

    def ready(self):
        session=LiveSession(bot_id='current-quest')
        session.bind_source(admission.SOURCE)
        session.publish(owner())
        self.addCleanup(session.close)
        person=session.snapshot()['character']
        session.packet(1854,body(key=110110),character_key=int(person['key']),world_id=person['world_id'])
        return session,person

    def test_current_codecs_remain_scoped_and_inside_proven_bounds(self):
        args=dict(source_sha256=admission.SOURCE,max_collection_items=8,max_total_items=72,max_payload_size=2530)
        with self.assertRaisesRegex(ValueError,'Unsupported'):decode_quest_sync(body(),**args)
        with admitted():
            self.assertEqual(len(decode_quest_sync(body(),**args).groups),1)
            for key,value in [('max_collection_items',9),('max_total_items',73),('max_payload_size',2531)]:
                with self.assertRaisesRegex(ValueError,'qualified'):decode_quest_sync(body(),**dict(args,**{key:value}))
            with self.assertRaisesRegex(ValueError,'qualified'):
                decode_tutorial_update(bytes(3),source_sha256=admission.SOURCE,max_records=65,max_payload_size=835)

    def test_snapshot_source_selection_stop_and_authoritative_death(self):
        with admitted():
            session,person=self.ready()
            state=session.snapshot()
            self.assertEqual(state['quest_snapshot']['source_sha256'],admission.SOURCE)
            self.assertEqual(state['coverage']['quests'],'last_received_message')
            self.assertFalse(state['interaction']['actions_ready'])
            self.assertEqual(state['interaction']['actions'],[])
            session.packet(9905,struct.pack('<BHIIIB',1,1,1001,0,1001002,1),
                character_key=int(person['key']),world_id=person['world_id'])
            self.assertEqual(session.snapshot()['tutorial']['source_sha256'],admission.SOURCE)
            selected=session.configure_quest_automation('110110',True)
            self.assertEqual(selected['automation']['state'],'waiting_data')
            self.assertTrue(selected['policy']['auto_quests'])
            stopped=session.configure_quest_automation(None,False)
            self.assertIsNone(stopped['automation']['selected_quest_id'])
            self.assertFalse(stopped['policy']['auto_quests'])
            session.configure_quest_automation('110110',True)
            key=int(person['key'])
            session.packet(322,struct.pack('<QHiqqBH',key,1,4,2700,0,0,0),character_key=key)
            dead=session.snapshot()
            self.assertEqual(dead['interaction']['automation']['state'],'dead')
            self.assertFalse(dead['action_policy']['auto_quests'])
            session.packet(322,struct.pack('<QHiqqBH',key,1,4,0,2700,0,0),character_key=key)
            self.assertFalse(session.snapshot()['action_policy']['auto_quests'])
            self.assertEqual(session.snapshot()['interaction']['automation']['state'],'paused')

    def test_loopback_scope_and_policy_only_without_action_installation(self):
        with admitted():session,person=self.ready()
        # HTTP runs on a different thread: observation admission was pinned by
        # the worker, while a policy command never calls a decoder/transport.
        with LiveSessionServer(session,port=0) as server:
            token=self.token(server,session)
            self.assertEqual(self.post(server,session,'0'*64,'quest-automation',dict(quest_id='110110',enabled=True))[0],403)
            self.assertEqual(self.post(server,session,token,'quest-automation',dict(quest_id='999',enabled=True))[0],400)
            code,result=self.post(server,session,token,'quest-automation',dict(quest_id='110110',enabled=True))
            self.assertEqual(code,202)
            self.assertEqual(result['status'],'quest_automation_updated')
            self.assertEqual(result['automation']['stop_reason'],'not_admitted')
            self.assertEqual(self.post(server,session,token,'policy',dict(policy=dict(skip_dialogues=False,auto_quests=True)))[0],202)
            stopped=self.post(server,session,token,'quest-automation',dict(quest_id=None,enabled=False))[1]
            self.assertFalse(stopped['policy']['auto_quests'])
            self.assertIsNone(stopped['automation']['selected_quest_id'])
            self.assertIsNone(session._actions)

    def test_only_queued_intents_cancel_sent_outcomes_survive(self):
        from vampir_core.action_queue import SessionActionQueue
        key=object()
        queue=SessionActionQueue(bot_id='fixture',session_id='1'*32,source_sha256='2'*64,
            owner_key=key,contracts={'quest_follow':'3'*64})
        def enqueue(request):
            return queue.enqueue(bot_id='fixture',session_id='1'*32,request_id=request*32,
                kind='quest_follow',context='4'*64,arguments={'quest_id':'110110'})
        enqueue('a');queue.claim(key,context='4'*64);queue.sent(key,'a'*32)
        enqueue('b');queue.cancel_pending(key)
        self.assertEqual([row['status'] for row in queue.snapshot()['records']],['sent','failed'])
        queue.resolve(key,'a'*32,status='unknown');queue.cancel_pending(key)
        self.assertTrue(queue.snapshot()['blocked'])
        self.assertEqual(queue.snapshot()['records'][0]['status'],'unknown')

    def test_panel_proxy_retains_owner_identity_and_hides_tokens(self):
        path=Path(__file__).parent/'vampir-headless/account_world.py'
        spec=importlib.util.spec_from_file_location('quest_panel_world',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with admitted():session,_=self.ready()
        with tempfile.TemporaryDirectory() as folder, LiveSessionServer(session,port=0) as server:
            control=module.WorldControl(SimpleNamespace(path=Path(folder)/'store.sqlite3'))
            row=dict(state='connected',session_id=session.session_id,port=server.server.server_port)
            control.snapshot=lambda **kwargs:{session.bot_id:row}
            response=control.command(session.bot_id,session.session_id,'quest-automation',dict(quest_id='110110',enabled=True))
            self.assertEqual(response['automation']['selected_quest_id'],'110110')
            self.assertNotIn('token',json.dumps(response))
            with self.assertRaisesRegex(ValueError,'изменилась'):
                control.command(session.bot_id,'stale','quest-automation',dict(quest_id=None,enabled=False))
            with self.assertRaisesRegex(ValueError,'Контекст'):
                control.command(session.bot_id,session.session_id,'quest-automation',dict(bot_id='other'))

    def test_owner_continues_only_after_confirmed_first_click_and_new_offer(self):
        import test_vampir_quest_owner_pump as fixture
        from vampir_core.quest_update import QuestUpdate
        from test_vampir_quest_observations import sync
        helper=fixture.QuestOwnerPumpTests();self.addCleanup(helper.doCleanups)
        s,key,connection,peer,offer=helper.offered()
        s.configure_quest_automation('110120',True)
        self.assertIsNone(s.pump_quest_actions(connection))
        self.assertEqual(connection.queued_bytes,0)
        first=helper.intent(offer);s.enqueue_action(first)
        self.assertEqual(s.pump_quest_actions(connection)['status'],'sent')
        connection.pump(now=7,budget=fixture.wire.BUDGET);helper.read_request(peer,7)
        person=s.snapshot()['character']
        s.packet(1854,sync(1),character_key=int(person['key']),world_id=person['world_id'])
        s.offer_quest_step(key,payload=QuestUpdate((1,2,3),0,110120,1))
        # A new state alone does not assert a successful earlier action.
        self.assertIsNone(s.pump_quest_actions(connection))
        self.assertEqual(connection.queued_bytes,0)
        s.resolve_action(key,first['request_id'],status='confirmed')
        second=s.pump_quest_actions(connection)
        self.assertEqual(second['status'],'sent')
        self.assertNotEqual(second['request_id'],first['request_id'])
        self.assertIsNone(s.pump_quest_actions(connection))
        connection.pump(now=7,budget=fixture.wire.BUDGET);helper.read_request(peer,7)
        s.configure_quest_automation(None,False)
        s.resolve_action(key,second['request_id'],status='confirmed')
        s.packet(1854,sync(2),character_key=int(person['key']),world_id=person['world_id'])
        s.offer_quest_step(key,payload=QuestUpdate((1,2,3),0,110120,2))
        self.assertIsNone(s.pump_quest_actions(connection))
        self.assertEqual(connection.queued_bytes,0)

    def test_unknown_action_blocks_automatic_next_step(self):
        import test_vampir_quest_owner_pump as fixture
        from vampir_core.quest_update import QuestUpdate
        from test_vampir_quest_observations import sync
        helper=fixture.QuestOwnerPumpTests();self.addCleanup(helper.doCleanups)
        s,key,connection,peer,offer=helper.offered()
        s.configure_quest_automation('110120',True)
        first=helper.intent(offer);s.enqueue_action(first);s.pump_quest_actions(connection)
        connection.pump(now=7,budget=fixture.wire.BUDGET);helper.read_request(peer,7)
        s.resolve_action(key,first['request_id'],status='unknown')
        person=s.snapshot()['character']
        s.packet(1854,sync(1),character_key=int(person['key']),world_id=person['world_id'])
        s.offer_quest_step(key,payload=QuestUpdate((1,2,3),0,110120,1))
        self.assertIsNone(s.pump_quest_actions(connection))
        self.assertEqual(connection.queued_bytes,0)
        self.assertEqual(s.snapshot()['interaction']['automation']['state'],'unknown')


if __name__=='__main__':unittest.main()
