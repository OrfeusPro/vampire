"""Real one-shot task launch and ancestry boundary; no game or account IO."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.request import urlopen

SHARED=Path(__file__).parent/'vampir-shared'
sys.path.insert(0,str(SHARED))
from vampir_core.scheduled_worker import launch_scheduled,task_call


@unittest.skipUnless(os.name=='nt','Windows interactive task semantics')
class ScheduledWorkerTests(unittest.TestCase):
    def test_timeout_stops_own_task_and_rejects_invalid_input_before_registration(self):
        with patch('vampir_core.scheduled_worker.task_call') as register:
            with self.assertRaises(ValueError):launch_scheduled(['other.exe'],{})
            register.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            worker=Path(directory)/'silent.py';worker.write_text('import time;time.sleep(40)','utf-8')
            calls=[]
            def recorded(spec):calls.append(spec.copy());return task_call(spec)
            with patch('vampir_core.scheduled_worker.task_call',side_effect=recorded):
                with self.assertRaises(TimeoutError):
                    launch_scheduled([sys.executable,'-X','utf8',str(worker)],{},timeout=.3)
            self.assertEqual(calls[-1],dict(mode='cleanup',name=calls[0]['name'],stop=True))

    def test_worker_survives_dispatcher_tree_termination(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);worker=root/'worker.py';dispatcher=root/'dispatcher.py';notice_path=root/'ready.json'
            worker.write_text('''import sys,os,threading
sys.path.insert(0,sys.argv[1])
from vampir_core.detached_worker import receive_handoff,ready_channel
from http.server import HTTPServer,BaseHTTPRequestHandler
ready=ready_channel();payload=receive_handoff(sys.stdin.buffer)
assert payload=={'secret':'synthetic-秘密'}
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b'alive')
  if self.path=='/stop':threading.Thread(target=self.server.shutdown,daemon=True).start()
with HTTPServer(('127.0.0.1',0),Handler) as server:
 timer=threading.Timer(45,server.shutdown);timer.daemon=True;timer.start()
 ready({'status':'ready','pid':os.getpid(),'port':server.server_port})
 try:server.serve_forever(poll_interval=.05)
 finally:timer.cancel()
''',encoding='utf-8')
            dispatcher.write_text('''import sys,json,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from vampir_core.scheduled_worker import launch_scheduled
ready=launch_scheduled([sys.executable,'-X','utf8',sys.argv[2],sys.argv[1]],{'secret':'synthetic-秘密'})
Path(sys.argv[3]).write_text(json.dumps(ready),'utf-8')
time.sleep(50)
''',encoding='utf-8')
            dispatch=subprocess.Popen([sys.executable,'-X','utf8',str(dispatcher),str(SHARED.resolve()),str(worker),str(notice_path)],
                stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            base=None
            try:
                deadline=time.monotonic()+35
                while not notice_path.is_file() and dispatch.poll() is None and time.monotonic()<deadline:time.sleep(.05)
                if not notice_path.is_file():
                    if dispatch.poll() is None:dispatch.terminate()
                    dispatch.wait(timeout=5)
                    self.fail('Task startup failed: '+dispatch.stderr.read().decode('utf-8','replace'))
                notice=json.loads(notice_path.read_text('utf-8'));base='http://127.0.0.1:'+str(notice['port'])
                self.assertEqual(notice['launcher'],'windows_interactive_task')
                result=subprocess.run(['taskkill','/PID',str(dispatch.pid),'/T','/F'],capture_output=True,timeout=5)
                self.assertEqual(result.returncode,0)
                dispatch.wait(timeout=5)
                with urlopen(base+'/alive',timeout=3) as response:self.assertEqual(response.read(),b'alive')
            finally:
                if dispatch.poll() is None:dispatch.terminate();dispatch.wait(timeout=5)
                if base:
                    with urlopen(base+'/stop',timeout=3) as response:self.assertEqual(response.status,200)
                dispatch.stderr.close()


if __name__=='__main__':unittest.main()
