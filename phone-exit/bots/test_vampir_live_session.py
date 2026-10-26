import http.client
import json
import unittest
import struct
import importlib.util
import io
from contextlib import redirect_stdout
from pathlib import Path
from threading import Barrier,Event,Lock
from types import SimpleNamespace as N

from vampir_core.live_session import LiveSession, LiveSessions
from vampir_core.live_session_server import LiveSessionServer


def owner(key=42,stats=()):
    position=N(world_id=10010,vector=N(finite_values=lambda:(1.,2.,3.)))
    return N(world_entry=N(state='finish_response',target_position=position),
        selection=N(response=N(player=N(at=lambda offset:{8:key,0x1c8:stats}[offset])),
            characters=N(records=[N(u64=[key],strings=['Персонаж'])])),
        heartbeat=N(queued_count=3,response_count=2))


class LiveSessionTests(unittest.TestCase):
    def test_readiness_precedes_workers_and_lifetime_stops_owner(self):
        import time
        from urllib.request import urlopen
        path=Path(__file__).parent/'vampir-headless/run-live-sessions.py'
        spec=importlib.util.spec_from_file_location('test_live_lifetime',path)
        launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)
        accounts=[dict(bot_id='limited',email='fixture@example.com',socks_port=1087,region='JP',server_id=256,character_index=0)]
        notices=[]
        def ready(value):
            with urlopen('http://127.0.0.1:'+str(value['port'])+'/sessions',timeout=2) as response:
                notices.append(json.load(response))
        def run(email,**kwargs):
            self.assertEqual(len(notices),1)
            session=kwargs['session_control'];deadline=time.monotonic()+3
            while not session.stop_requested and time.monotonic()<deadline:time.sleep(.01)
            self.assertTrue(session.stop_requested)
            return dict(status='fixture',game=dict(status='session_stopped'))
        passwords={'limited':'synthetic'}
        with redirect_stdout(io.StringIO()):
            result=launcher.run_accounts(accounts,passwords,manifest=Path('fixture'),client_version=1,
                probe=N(run=run),port=0,max_runtime_seconds=1,ready_callback=ready)
        self.assertFalse(passwords);self.assertEqual(result[0]['game_status'],'session_stopped')
        self.assertEqual(notices[0]['sessions'][0]['state'],'connecting')

    def test_fifty_fixture_worlds_keep_individual_stats_with_bounded_sign_in(self):
        import time
        from vampir_core.stat_change import SOURCE_SHA256
        path=Path(__file__).parent/'vampir-headless/run-live-sessions.py'
        spec=importlib.util.spec_from_file_location('test_live_fifty',path)
        launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)
        accounts=[dict(bot_id='bot-'+str(i),email=str(i)+'@example.com',socks_port=20000+i,region='JP',server_id=256,character_index=0) for i in range(50)]
        lock=Lock();ready=Barrier(50);active=0;peak=0;seen={}
        def run(email,**kwargs):
            nonlocal active,peak
            with lock:active+=1;peak=max(peak,active)
            time.sleep(.003)
            with lock:active-=1
            kwargs['_progress']('game_login_exchange')
            session=kwargs['session_control'];i=int(email.split('@')[0])
            session.bind_source(SOURCE_SHA256)
            body=struct.pack('<QHiqqBH',42,1,4,0,i,0,0)
            session.packet(322,body,character_key=42);session.publish(owner())
            ready.wait(5)
            with lock:seen[session.bot_id]=session.snapshot()['character']['hp']
            session.request_stop()
            return dict(status='fixture',game=dict(status='session_stopped'))
        with redirect_stdout(io.StringIO()):
            result=launcher.run_accounts(accounts,{row['bot_id']:'fixture' for row in accounts},manifest=Path('fixture'),client_version=1,probe=N(run=run),port=0)
        self.assertEqual(len(result),50)
        self.assertTrue(all(row.get('game_status')=='session_stopped' for row in result))
        self.assertEqual(seen,{'bot-'+str(i):i for i in range(50)})
        self.assertLessEqual(peak,2)

    def test_initial_values_do_not_overwrite_changes_and_are_cleared_on_disconnect(self):
        from vampir_core.stat_change import SOURCE_SHA256
        from vampir_core.character_select_result import SelectionRecord
        stats=tuple(SelectionRecord(((8,stat),(16,value))) for stat,value in [(3,12),(4,90),(5,100),(9,25),(10,50)])
        session=LiveSession(bot_id='initial');session.bind_source(SOURCE_SHA256)
        body=struct.pack('<QHiqqBH',42,1,4,90,80,0,0)
        session.packet(322,body,character_key=42)
        session.publish(owner(stats=stats))
        state=session.snapshot()
        self.assertEqual(state['character']['hp'],80)
        self.assertEqual(state['character']['max_hp'],100)
        self.assertEqual(state['character']['level'],12)
        self.assertEqual(state['coverage']['vitals'],'received')
        session.packet(322,b'bad',character_key=42)
        session.publish(owner(stats=stats))
        self.assertIsNone(session.snapshot()['character']['hp'])
        session.close();self.assertIsNone(session.snapshot()['character'])

    def test_current_stats_are_bound_to_character_and_account_before_publication(self):
        from vampir_core.stat_change import SOURCE_SHA256
        def body(key,values):
            return struct.pack('<QH',key,len(values))+b''.join(struct.pack('<iqq',stat,999,value) for stat,value in values)+bytes(3)
        a,b=LiveSession(bot_id='a'),LiveSession(bot_id='b')
        for session in (a,b):session.bind_source(SOURCE_SHA256)
        values=[(3,12),(4,0),(5,100),(9,25),(10,50)]
        a.packet(322,body(42,values),character_key=42)
        self.assertIsNone(a.snapshot()['character'])
        a.publish(owner());b.publish(owner())
        self.assertEqual([a.snapshot()['character'][k] for k in ('level','hp','max_hp','mp','max_mp')],[12,0,100,25,50])
        self.assertIsNone(b.snapshot()['character']['hp'])
        self.assertEqual(a.snapshot()['coverage']['vitals'],'received')
        self.assertEqual(a.snapshot()['character']['stats'][1]['name'],'Hp')
        a.packet(322,body(777,[(4,99999)]),character_key=42)
        self.assertEqual(a.snapshot()['character']['hp'],0)
        a.packet(322,body(42,[(4,30),(4,40),(10,2**63-1)]),character_key=42)
        self.assertEqual(a.snapshot()['character']['hp'],40)
        self.assertIsNone(a.snapshot()['character']['max_mp'])
        self.assertEqual(a.snapshot()['character']['stats'][-1]['value'],str(2**63-1))
        a.publish(owner())
        self.assertEqual(a.snapshot()['character']['hp'],40)
        a.packet(322,b'bad',character_key=42)
        self.assertIsNone(a.snapshot()['character']['hp'])
        self.assertEqual(a.snapshot()['coverage']['stats'],'decode_error')
        a.close();self.assertIsNone(a.snapshot()['character'])
        with self.assertRaises(ValueError):b.bind_source('a'*64)

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
