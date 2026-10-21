"""Explicit read-only loopback map feed; coordinates stay in memory."""
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from threading import Lock, Thread
import time


class MapSession:
    def __init__(self,projection):
        self.projection=projection
        self._lock=Lock()
        self._snapshot=dict(schema=1,state='waiting',position=None,updated_at_ms=None)

    def update(self,position):
        try:projected=asdict(self.projection.project(position))
        except ValueError:
            with self._lock:self._snapshot=dict(schema=1,state='unsupported_world',position=None,updated_at_ms=None)
            return
        with self._lock:
            self._snapshot=dict(schema=1,state='connected',position=projected,
                updated_at_ms=time.time_ns()//1000000)

    def disconnect(self):
        with self._lock:self._snapshot=dict(schema=1,state='disconnected',position=None,updated_at_ms=None)

    def snapshot(self):
        with self._lock:return json.loads(json.dumps(self._snapshot,allow_nan=False))


class MapSessionServer:
    """Own a bounded single-request server. No files, credentials or commands."""
    def __init__(self,session,*,port=17947):
        if type(port) is not int or not 0<=port<=65535:raise ValueError('Invalid map feed port')
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                if self.headers.get('Host')!='127.0.0.1:'+str(self.server.server_port):
                    self.send_error(403);return
                origin=self.headers.get('Origin')
                if origin not in (None,'http://127.0.0.1:17946'):
                    self.send_error(403);return
                if self.path!='/state':self.send_error(404);return
                body=json.dumps(session.snapshot(),allow_nan=False,separators=(',',':')).encode()
                self.send_response(200)
                self.send_header('Content-Type','application/json; charset=utf-8')
                self.send_header('Content-Length',str(len(body)))
                self.send_header('Cache-Control','no-store')
                self.send_header('X-Content-Type-Options','nosniff')
                if origin:self.send_header('Access-Control-Allow-Origin',origin)
                self.send_header('Vary','Origin')
                self.end_headers();self.wfile.write(body)
            def setup(self):
                self.request.settimeout(2)
                super().setup()
        self.session=session
        self.server=HTTPServer(('127.0.0.1',port),Handler)
        self.thread=Thread(target=self.server.serve_forever,kwargs={'poll_interval':.1},daemon=True)

    def __enter__(self):
        self.thread.start();return self

    def __exit__(self,*args):
        self.session.disconnect()
        self.server.shutdown();self.server.server_close();self.thread.join(3)
        if self.thread.is_alive():raise RuntimeError('Map feed did not stop')
