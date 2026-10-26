"""Real Windows breakaway child, bounded synthetic handoff; no game IO."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.request import urlopen

SHARED=Path(__file__).parent/'vampir-shared'
sys.path.insert(0,str(SHARED))
from vampir_core.detached_worker import MAX_INPUT,launch_detached,receive_handoff


class HandoffTests(unittest.TestCase):
    def test_input_bounds_and_type(self):
        self.assertEqual(receive_handoff(io.BytesIO(b'{"value":1}')),{'value':1})
        for value in (b'[]',b'x'*(MAX_INPUT+1)):
            with self.assertRaises(ValueError):receive_handoff(io.BytesIO(value))

    @unittest.skipUnless(os.name=='nt','Windows process-job semantics')
    def test_child_survives_dispatcher_exit_and_serves_until_explicit_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);worker=root/'worker.py';dispatcher=root/'dispatcher.py'
            worker.write_text('''import sys,json,os,threading
sys.path.insert(0,sys.argv[1])
from vampir_core.detached_worker import ready_channel,receive_handoff
from http.server import HTTPServer,BaseHTTPRequestHandler
ready=ready_channel();data=receive_handoff(sys.stdin.buffer)
assert data=={'password':'synthetic-秘密-test'}
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b'ok')
  if self.path=='/stop':threading.Thread(target=self.server.shutdown,daemon=True).start()
with HTTPServer(('127.0.0.1',0),Handler) as server:
 timer=threading.Timer(20,server.shutdown);timer.daemon=True;timer.start()
 ready({'status':'ready','pid':os.getpid(),'port':server.server_port})
 try:server.serve_forever(poll_interval=.05)
 finally:timer.cancel()
''',encoding='utf-8')
            dispatcher.write_text('''import sys,json
sys.path.insert(0,sys.argv[1])
from vampir_core.detached_worker import launch_detached
print(json.dumps(launch_detached([sys.executable,'-X','utf8',sys.argv[2],sys.argv[1]],{'password':'synthetic-秘密-test'})))
''',encoding='utf-8')
            result=subprocess.run([sys.executable,'-X','utf8',str(dispatcher),str(SHARED.resolve()),str(worker)],
                capture_output=True,text=True,encoding='utf-8',check=True,timeout=15)
            notice=json.loads(result.stdout)
            self.assertNotIn('synthetic',result.stdout+result.stderr)
            base='http://127.0.0.1:'+str(notice['port'])
            try:
                with urlopen(base+'/alive',timeout=3) as response:self.assertEqual(response.read(),b'ok')
                self.assertNotEqual(notice['pid'],os.getpid())
            finally:
                with urlopen(base+'/stop',timeout=3) as response:self.assertEqual(response.status,200)

    @unittest.skipUnless(os.name=='nt','Windows process-job semantics')
    def test_bad_or_oversized_handoff_does_not_leave_a_worker(self):
        with self.assertRaises(RuntimeError):
            launch_detached([sys.executable,'-c','import sys; sys.stdin.buffer.read(); print("wrong")'],{},timeout=3)
        with self.assertRaises(ValueError):
            launch_detached([sys.executable,'-c','raise AssertionError()'],{'secret':'x'*MAX_INPUT})
        with self.assertRaises(TimeoutError):
            launch_detached([sys.executable,'-c','import time; time.sleep(20)'],
                {'password':'x'*524288},timeout=.25)


if __name__=='__main__':unittest.main()
