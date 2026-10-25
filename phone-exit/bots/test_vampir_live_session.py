import http.client
import json
import unittest
import importlib.util
import io
from contextlib import redirect_stdout
from pathlib import Path
from threading import Barrier,Event
from types import SimpleNamespace as N

from vampir_core.live_session import LiveSession, LiveSessions
from vampir_core.live_session_server import LiveSessionServer


def owner(key=42):
    position=N(world_id=10010,vector=N(finite_values=lambda:(1.,2.,3.)))
    return N(world_entry=N(state='finish_response',target_position=position),
        selection=N(response=N(player=N(at=lambda offset:key)),
            characters=N(records=[N(u64=[key],strings=['Персонаж'])])),
        heartbeat=N(queued_count=3,response_count=2))


class LiveSessionTests(unittest.TestCase):
    def test_parallel_launcher_keeps_routes_and_credentials_separate(self):
        path=Path(__file__).parent/'vampir-headless/run-live-sessions.py'
        spec=importlib.util.spec_from_file_location('test_live_launcher',path)
        launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)
        accounts=[dict(bot_id=bot,email=bot+'@example.com',socks_port=port,region='JP',server_id=256,character_index=0)
            for bot,port in [('a',17948),('b',17949)]]
        ready=Barrier(2);a_finished=Event();seen={}
        def run(email,**kwargs):
            session=kwargs['session_control'];bot=session.bot_id
            seen[bot]=(email,kwargs['password'],kwargs['socks_port'],session.session_id)
            session.publish(owner(1 if bot=='a' else 2))
            ready.wait(3)
            if bot=='a':
                session.request_stop();a_finished.set()
            else:
                self.assertTrue(a_finished.wait(3))
                self.assertFalse(session.stop_requested)
                self.assertEqual(session.snapshot()['character']['key'],'2')
                session.request_stop()
            return dict(status='test',game=dict(status='session_stopped'))
        passwords={'a':'secret-a','b':'secret-b'}
        output=io.StringIO()
        with redirect_stdout(output):
            result=launcher.run_accounts(accounts,passwords,manifest=Path('fixture'),client_version=1,probe=N(run=run),port=0)
        self.assertEqual({r['game_status'] for r in result},{'session_stopped'})
        self.assertEqual(seen['a'][:3],('a@example.com','secret-a',17948))
        self.assertEqual(seen['b'][:3],('b@example.com','secret-b',17949))
        self.assertNotEqual(seen['a'][3],seen['b'][3])
        self.assertEqual(passwords,{})
        self.assertNotIn('secret-',output.getvalue())
        with self.assertRaises(ValueError):launcher.validate_accounts([accounts[0],accounts[0]])
        with self.assertRaises(ValueError):launcher.validate_accounts([{**accounts[0],'password':'forbidden'}])

    def test_unknown_vitals_and_packets_never_become_demo_values(self):
        session=LiveSession(bot_id='bot-a')
        session.publish(owner())
        session.packet(322,b'private-unverified-body')
        state=session.snapshot()
        self.assertEqual(state['character']['key'],'42')
        self.assertEqual(state['character']['name'],'Персонаж')
        for key in ['hp','mp','max_hp','max_mp','level']:
            self.assertIsNone(state['character'][key])
        self.assertEqual(state['entities'],[])
        self.assertEqual(state['coverage']['entities'],'not_verified')
        self.assertEqual(state['packets'],{'322':1})
        self.assertNotIn('private',json.dumps(state))
        state['character']['hp']=999
        self.assertIsNone(session.snapshot()['character']['hp'])
        session.close()
        session.publish(owner())
        self.assertEqual(session.snapshot()['state'],'disconnected')
        self.assertIsNone(session.snapshot()['character'])

    def test_registry_capacity_identity_and_stop_are_isolated(self):
        registry=LiveSessions(capacity=2)
        a,b=LiveSession(bot_id='a'),LiveSession(bot_id='b')
        registry.attach(a);registry.attach(b)
        a.publish(owner(1));b.publish(owner(2))
        a.request_stop()
        self.assertTrue(a.stop_requested)
        self.assertFalse(b.stop_requested)
        self.assertEqual(b.snapshot()['character']['key'],'2')
        with self.assertRaises(ValueError):registry.attach(a)
        with self.assertRaises(BufferError):registry.attach(LiveSession(bot_id='c'))
        registry.close()
        self.assertTrue(b.stop_requested)
        duplicate=LiveSessions()
        duplicate.attach(a)
        with self.assertRaises(ValueError):duplicate.attach(LiveSession(bot_id='c',session_id=a.session_id))

    def test_http_refuses_cross_session_stop_stale_identity_and_foreign_origin(self):
        registry=LiveSessions()
        a,b=LiveSession(bot_id='a'),LiveSession(bot_id='b')
        registry.attach(a);registry.attach(b)
        with LiveSessionServer(registry,port=0) as server:
            port=server.server.server_port
            def request(method,path,body=None,**headers):
                connection=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
                connection.request(method,path,body,headers)
                response=connection.getresponse()
                result=response.status,response.read()
                connection.close()
                return result
            status,raw=request('GET','/bots/a/control')
            self.assertEqual(status,200)
            control=json.loads(raw)
            headers={'X-Session-Token':control['token'],'Content-Type':'application/json'}
            self.assertEqual(request('GET','/state')[0],404)
            self.assertEqual(request('GET','/bots/a/state',Origin='https://foreign.example')[0],403)
            self.assertEqual(request('GET','/bots/a/state',Host='foreign.example')[0],403)
            self.assertEqual(request('POST','/bots/b/stop',json.dumps(dict(bot_id='b',session_id=b.session_id)),**headers)[0],403)
            self.assertEqual(request('POST','/bots/a/stop',json.dumps(dict(bot_id='a',session_id='stale')),**headers)[0],400)
            self.assertFalse(a.stop_requested);self.assertFalse(b.stop_requested)
            body=json.dumps(dict(bot_id='a',session_id=a.session_id))
            self.assertEqual(request('POST','/bots/a/stop',body,**headers)[0],202)
            self.assertTrue(a.stop_requested);self.assertFalse(b.stop_requested)
        self.assertTrue(b.stop_requested)


if __name__=='__main__':unittest.main()
