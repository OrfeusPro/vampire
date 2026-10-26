"""Real loopback API, synthetic owner contracts; never contacts a game server."""
import http.client
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.live_session import LiveSession,LiveSessions
from vampir_core.live_session_server import LiveSessionServer
from test_vampir_live_session import owner

SOURCE='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
CONTEXT='b'*64
POLICY=dict(skip_dialogues=True,auto_quests=False)
OFFER=dict(kind='dialogue_skip',context=CONTEXT,arguments={'dialogue_id':'7'})


def prepare(index=0):
    session=LiveSession(bot_id='api'+str(index));session.bind_source(SOURCE);session.publish(owner(index+1))
    key=object();session.install_actions(key,contracts={'dialogue_skip':'a'*64})
    session.offer_actions(key,[OFFER]);return session,key


def intent(index=1,**changes):
    return dict(request_id=f'{index:032x}',**OFFER,policy=POLICY.copy(),origin='manual',**changes)


class ActionApiTests(unittest.TestCase):
    def request(self,server,method,path,value=None,token=None,origin='http://127.0.0.1:17946'):
        connection=http.client.HTTPConnection('127.0.0.1',server.server.server_port,timeout=3)
        headers={'Origin':origin,'Content-Type':'application/json'}
        if token is not None:headers['X-Session-Token']=token
        connection.request(method,path,json.dumps(value) if value is not None else None,headers)
        response=connection.getresponse();status=response.status;raw=response.read();connection.close()
        return status,json.loads(raw) if status<300 else None

    def post(self,server,session,token,action,value,**options):
        return self.request(server,'POST','/bots/'+session.bot_id+'/'+action,
            dict(bot_id=session.bot_id,session_id=session.session_id,**value),token,**options)

    def token(self,server,session):
        status,value=self.request(server,'GET','/bots/'+session.bot_id+'/control')
        self.assertEqual(status,200);self.assertRegex(value['token'],r'^[a-f0-9]{64}$');return value['token']

    def test_fifty_http_queues_are_isolated_and_only_owner_confirms(self):
        registry=LiveSessions(capacity=50);pairs=[prepare(i) for i in range(50)]
        for session,key in pairs:registry.attach(session)
        with LiveSessionServer(registry,port=0) as server:
            tokens=[self.token(server,session) for session,key in pairs]
            self.assertEqual(len(set(tokens)),50)
            for (session,key),token in zip(pairs,tokens):
                status,queued=self.post(server,session,token,'actions',intent())
                self.assertEqual(status,202);self.assertEqual(queued['status'],'queued')
                self.assertEqual(self.post(server,session,token,'actions',intent())[1],queued)
                self.assertEqual(self.post(server,session,token,'actions',{**intent(),'arguments':{'dialogue_id':'8'}})[0],400)
                with self.assertRaises(RuntimeError):session.claim_action(object(),context=CONTEXT)
                taken=session.claim_action(key,context=CONTEXT)
                self.assertEqual(taken['policy'],POLICY);self.assertEqual(taken['current_policy'],POLICY)
                self.assertEqual(taken['origin'],'manual')
                session.action_sent(key,taken['request_id']);session.resolve_action(key,taken['request_id'],status='confirmed')
                session.offer_actions(key,[])
                self.assertEqual(self.post(server,session,token,'actions',intent())[1]['status'],'confirmed')
                status,state=self.request(server,'GET','/bots/'+session.bot_id+'/state')
                self.assertEqual(state['action_queue']['records'][0]['status'],'confirmed')
                self.assertEqual(state['action_queue']['bot_id'],session.bot_id)
            self.assertEqual(self.post(server,pairs[1][0],tokens[0],'actions',intent(2))[0],403)
            self.assertTrue(all(not session.stop_requested for session,key in pairs))

    def test_policy_changes_fence_queued_auto_skip_and_never_start_quests(self):
        session,key=prepare()
        with LiveSessionServer(session,port=0) as server:
            token=self.token(server,session)
            value={**intent(),'origin':'auto_skip'}
            self.assertEqual(self.post(server,session,token,'actions',value)[0],202)
            policy=dict(skip_dialogues=False,auto_quests=True)
            status,result=self.post(server,session,token,'policy',dict(policy=policy))
            self.assertEqual(status,202);self.assertEqual(result['policy'],policy)
            self.assertIsNone(session.claim_action(key,context=CONTEXT))
            self.assertEqual(session.snapshot()['action_queue']['records'][0]['status'],'failed')
            self.assertEqual(self.post(server,session,token,'actions',{**value,'request_id':'e'*32})[0],409)
            self.assertEqual(len(session.snapshot()['action_queue']['records']),1)
            self.assertEqual(self.post(server,session,token,'policy',dict(policy={'skip_dialogues':1,'auto_quests':True}))[0],400)
            self.assertEqual(session.snapshot()['action_policy'],policy)

    def test_changed_offers_scope_and_disconnect_reject_stale_intents(self):
        session,key=prepare()
        session.enqueue_action(intent());session.offer_actions(key,[])
        self.assertIsNone(session.claim_action(key,context=CONTEXT))
        self.assertEqual(session.enqueue_action(intent())['status'],'failed')
        session.offer_actions(key,[OFFER]);session.enqueue_action(intent(2))
        moved=owner(1);moved.world_entry.target_position.world_id=10012;session.publish(moved)
        with self.assertRaises(RuntimeError):session.enqueue_action(intent(3))
        # Returning to the same world does not revive offers from that visit.
        session.publish(owner(1))
        with self.assertRaises(RuntimeError):session.enqueue_action(intent(3))
        self.assertIsNone(session.claim_action(key,context=CONTEXT))
        session.offer_actions(key,[OFFER]);session.enqueue_action(intent(4))
        taken=session.claim_action(key,context=CONTEXT);session.action_sent(key,taken['request_id'])
        session.close()
        self.assertEqual(session.snapshot()['action_queue']['records'][-1]['status'],'unknown')
        with self.assertRaises(RuntimeError):session.enqueue_action(intent(5))

    def test_default_owner_has_no_channel_and_http_cannot_install_or_resolve(self):
        session=LiveSession(bot_id='plain');session.bind_source(SOURCE);session.publish(owner())
        with LiveSessionServer(session,port=0) as server:
            token=self.token(server,session)
            self.assertEqual(self.post(server,session,token,'actions',intent())[0],409)
            self.assertEqual(self.post(server,session,token,'policy',dict(policy=POLICY))[0],409)
            self.assertEqual(self.post(server,session,token,'actions',dict(contracts={'dialogue_skip':'a'*64}))[0],400)
            self.assertEqual(self.post(server,session,token,'actions',intent(),origin='https://foreign.example')[0],403)
            self.assertEqual(self.post(server,session,token,'actions',{**intent(),'status':'confirmed'})[0],400)
            self.assertNotIn('action_queue',session.snapshot())
        session,key=prepare()
        session.enqueue_action(intent())
        with self.assertRaises(ValueError):session.enqueue_action({**intent(),'policy':dict(skip_dialogues=True,auto_quests=True)})
        self.assertEqual(session.claim_action(key,context=CONTEXT)['policy'],POLICY)

    def test_unknown_requires_owner_sync_with_new_offered_context(self):
        session,key=prepare();session.enqueue_action(intent())
        taken=session.claim_action(key,context=CONTEXT);session.action_sent(key,taken['request_id'])
        session.resolve_action(key,taken['request_id'],status='unknown')
        with self.assertRaises(RuntimeError):session.enqueue_action(intent(2))
        with self.assertRaises(RuntimeError):session.resume_actions_after_sync(key,context=CONTEXT)
        changed={**OFFER,'context':'c'*64};session.offer_actions(key,[changed])
        with self.assertRaises(RuntimeError):session.resume_actions_after_sync(object(),context='c'*64)
        session.resume_actions_after_sync(key,context='c'*64)
        session.enqueue_action({**intent(2),'context':'c'*64})
        self.assertEqual(session.claim_action(key,context='c'*64)['request_id'],f'{2:032x}')
        self.assertEqual(session.snapshot()['action_queue']['records'][0]['status'],'unknown')


if __name__=='__main__':unittest.main()
