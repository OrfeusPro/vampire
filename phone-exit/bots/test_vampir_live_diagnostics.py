"""Live observer isolation, bounded capture and in-place code edits; offline."""
import base64
import http.client
import importlib.util
import json
from pathlib import Path
import tempfile
from threading import Event,Thread
import time
import unittest

from vampir_core.live_session import LiveSession,LiveSessions
from vampir_core.live_session_server import LiveSessionServer
from vampir_core.live_diagnostics import LiveDiagnostics
from test_vampir_live_session import owner


class LiveDiagnosticsTests(unittest.TestCase):
    def test_journal_is_bounded_cursor_reports_gaps_and_auth_body_is_absent(self):
        session=LiveSession(bot_id='a')
        for i in range(300):session.packet(13,b'secret-auth-token')
        journal=session.journal()
        self.assertEqual(len(journal['events']),128);self.assertTrue(journal['gap'])
        self.assertEqual(journal['oldest'],46)
        self.assertNotIn('secret',json.dumps(session.snapshot()))
        rest=session.journal(journal['cursor'])
        self.assertEqual(len(rest['events']),128)
        self.assertEqual(session.journal(rest['cursor'])['events'],[])
        with self.assertRaises(ValueError):session.journal(-1)

    def test_samples_are_explicit_leased_bounded_expiring_and_isolated(self):
        a,b=LiveDiagnostics(),LiveDiagnostics();lease='a'*32
        a.packet(322,b'not-enabled');self.assertEqual(len(a.samples),0)
        with self.assertRaises(ValueError):a.trace(lease,[13])
        a.trace(lease,[322])
        for i in range(10):a.packet(322,bytes([i])*65536)
        self.assertEqual(a.sample_bytes,262144)
        result=a.read_samples(lease,0)
        self.assertTrue(result['gap']);self.assertEqual(result['samples'][0]['seq'],7)
        self.assertEqual(base64.b64decode(result['samples'][0]['body_base64']),bytes([6])*65536)
        self.assertLess(len(json.dumps(result)),262144)
        self.assertEqual(len(b.samples),0)
        with self.assertRaises(RuntimeError):a.trace('b'*32,[322])
        with self.assertRaises(RuntimeError):a.read_samples('b'*32,0)
        a.until=0;a.expire()
        self.assertIsNone(a.lease);self.assertEqual(a.sample_bytes,0)
        self.assertEqual(a.events[-1]['kind'],'trace_expired')
        a.trace(lease,[322]);a.packet(322,b'private');a.close()
        self.assertFalse(a.samples)

    def test_analysis_expires_and_value_changes_do_not_claim_code_reload(self):
        session=LiveSession(bot_id='a')
        value=dict(revision='a'*64,values={'hp_percent':50},error=None)
        session.analysis(value)
        sequence=session.journal()['cursor']
        session.analysis(dict(value,values={'hp_percent':51}))
        self.assertEqual(session.journal()['cursor'],sequence)
        session._diagnostics.analysis_until=0
        self.assertIsNone(session.snapshot()['analysis'])
        self.assertEqual(session.journal()['events'][-1]['kind'],'analysis_expired')

    def test_api_requires_session_token_and_never_executes_arbitrary_code(self):
        a,b=LiveSession(bot_id='a'),LiveSession(bot_id='b');registry=LiveSessions()
        registry.attach(a);registry.attach(b)
        with LiveSessionServer(registry,port=0) as server:
            def request(method,path,value=None,token=None):
                conn=http.client.HTTPConnection('127.0.0.1',server.server.server_port,timeout=3)
                conn.request(method,path,None if value is None else json.dumps(value),
                    {'Content-Type':'application/json',**({'X-Session-Token':token} if token else {})})
                response=conn.getresponse();status=response.status;raw=response.read();conn.close()
                return status,json.loads(raw) if status==200 or status==202 else None
            token=request('GET','/bots/a/control')[1]['token']
            identity=dict(bot_id='a',session_id=a.session_id);lease='c'*32
            value=dict(identity,lease=lease,packet_ids=[322])
            self.assertEqual(request('POST','/bots/a/trace',value)[0],403)
            self.assertEqual(request('POST','/bots/b/trace',dict(value,bot_id='b',session_id=b.session_id),token)[0],403)
            self.assertEqual(request('POST','/bots/a/trace',dict(value,session_id='stale'),token)[0],400)
            self.assertEqual(request('POST','/bots/a/trace',value,token)[0],202)
            a.packet(322,b'world-sample')
            path='/bots/a/samples?session='+a.session_id+'&lease='+lease
            self.assertEqual(request('GET',path)[0],403)
            self.assertEqual(request('GET',path,token=token)[1]['samples'][0]['body_base64'],base64.b64encode(b'world-sample').decode())
            self.assertEqual(request('GET','/bots/a/events?session=stale')[0],400)
            self.assertEqual(request('POST','/bots/a/analysis',dict(identity,path='arbitrary.py'),token)[0],400)
            analysis=dict(identity,revision='d'*64,values={'hp_percent':50},error=None)
            self.assertEqual(request('POST','/bots/a/analysis',analysis,token)[0],202)
            self.assertEqual(a.snapshot()['analysis']['values'],{'hp_percent':50})
            self.assertIsNone(b.snapshot()['analysis'])
            self.assertFalse(a.stop_requested);self.assertFalse(b.stop_requested)
            a.close()
            self.assertEqual(request('POST','/bots/a/analysis',analysis,token)[0],409)

    def test_code_reloads_failures_timeout_and_worker_exit_leave_owner_running(self):
        path=Path(__file__).parent/'vampir-headless/watch-live-session.py'
        spec=importlib.util.spec_from_file_location('test_live_watch',path)
        watcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(watcher)
        session=LiveSession(bot_id='a');stop=Event();ticks=[]
        def pump():
            while not stop.wait(.01):
                session.publish(owner());ticks.append(1)
        thread=Thread(target=pump);thread.start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                handler=Path(temp)/'handler.py'
                handler.write_text("def analyze(batch):\n return {'version':1,'bot':batch['state']['bot_id']}\n",encoding='utf-8')
                first=watcher.evaluate(handler,dict(state=session.snapshot()))
                self.assertEqual(first['values'],{'version':1,'bot':'a'})
                handler.write_text("def analyze(batch):\n return {'version':2,'bot':batch['state']['bot_id']}\n",encoding='utf-8')
                second=watcher.evaluate(handler,dict(state=session.snapshot()))
                self.assertEqual(second['values']['version'],2);self.assertNotEqual(first['revision'],second['revision'])
                helper=Path(temp)/'helper.py';helper.write_text('VALUE=1\n',encoding='utf-8')
                import py_compile,os
                py_compile.compile(str(helper),doraise=True);stamp=helper.stat().st_mtime_ns
                helper.write_text('VALUE=2\n',encoding='utf-8');os.utime(helper,ns=(stamp,stamp))
                handler.write_text("import helper\ndef analyze(batch):\n return {'helper':helper.VALUE}\n",encoding='utf-8')
                self.assertEqual(watcher.evaluate(handler,{})['values'],{'helper':2})
                session.analysis(second);count=len(ticks)
                handler.write_text('def analyze(:',encoding='utf-8')
                failed=watcher.evaluate(handler,{})
                self.assertEqual(failed['error'],'SyntaxError');session.analysis(failed)
                handler.write_text('def analyze(batch):\n while True: pass\n',encoding='utf-8')
                self.assertEqual(watcher.evaluate(handler,{},timeout=.5)['error'],'HandlerTimeout')
                self.assertGreater(len(ticks),count);self.assertTrue(thread.is_alive())
                self.assertEqual(session.snapshot()['state'],'connected');self.assertFalse(session.stop_requested)
                self.assertEqual(session.snapshot()['session_id'],session.session_id)
        finally:stop.set();thread.join(3);session.close()


if __name__=='__main__':unittest.main()
