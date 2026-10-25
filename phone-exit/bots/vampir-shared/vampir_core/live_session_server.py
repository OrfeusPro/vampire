"""Loopback state/Stop API; HTTP never executes game operations."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import secrets
import re
from threading import Thread
from .live_session import LiveSession,LiveSessions


class LiveSessionServer:
    def __init__(self,session,*,port=17947):
        if type(port) is not int or not 0<=port<=65535:raise ValueError('Invalid session port')
        registry=session
        if isinstance(session,LiveSession):
            registry=LiveSessions();registry.attach(session)
        if not isinstance(registry,LiveSessions):raise TypeError('Expected isolated session registry')
        tokens={}
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def setup(self):
                self.request.settimeout(2);super().setup()
            def allowed(self):
                return (self.headers.get('Host')=='127.0.0.1:'+str(self.server.server_port)
                    and self.headers.get('Origin') in (None,'http://127.0.0.1:17946'))
            def selected(self):
                match=re.fullmatch('/bots/([a-zA-Z0-9_-]{1,48})/(state|control|stop)',self.path)
                if match:return registry.get(match[1]),match[2]
                # Legacy atlas endpoint is unambiguous only for one attached bot.
                listed=registry.list()
                if self.path=='/state' and len(listed)==1:return registry.get(listed[0]['bot_id']),'state'
                return None,None
            def send_json(self,status,value):
                body=json.dumps(value,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode()
                if len(body)>262144:status,body=503,b'{"error":"state_limit"}'
                self.send_response(status)
                self.send_header('Content-Type','application/json; charset=utf-8')
                self.send_header('Content-Length',str(len(body)))
                self.send_header('Cache-Control','no-store')
                self.send_header('X-Content-Type-Options','nosniff')
                origin=self.headers.get('Origin')
                if origin:self.send_header('Access-Control-Allow-Origin',origin)
                self.send_header('Vary','Origin');self.end_headers();self.wfile.write(body)
            def do_GET(self):
                if not self.allowed():self.send_error(403);return
                if self.path=='/sessions':self.send_json(200,dict(sessions=registry.list()));return
                selected,action=self.selected()
                if selected is None:self.send_error(404);return
                if action=='state':self.send_json(200,selected.snapshot())
                elif action=='control':
                    token=tokens.setdefault(selected.session_id,secrets.token_urlsafe(32))
                    self.send_json(200,dict(bot_id=selected.bot_id,session_id=selected.session_id,token=token,actions=['stop']))
                else:self.send_error(404)
            def do_OPTIONS(self):
                if not self.allowed():self.send_error(403);return
                self.send_response(204)
                self.send_header('Access-Control-Allow-Origin','http://127.0.0.1:17946')
                self.send_header('Access-Control-Allow-Methods','GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers','Content-Type, X-Session-Token')
                self.send_header('Vary','Origin');self.end_headers()
            def do_POST(self):
                selected,action=self.selected()
                token=tokens.get(selected.session_id) if selected else None
                if not self.allowed() or token is None or not secrets.compare_digest(self.headers.get('X-Session-Token',''),token):
                    self.send_error(403);return
                if action!='stop':self.send_error(404);return
                try:
                    size=int(self.headers.get('Content-Length','-1'))
                    if not 0<size<=1024:raise ValueError()
                    value=json.loads(self.rfile.read(size))
                    if value!={'bot_id':selected.bot_id,'session_id':selected.session_id}:raise ValueError()
                except (ValueError,UnicodeError):self.send_error(400);return
                selected.request_stop();self.send_json(202,dict(state='stopping'))
        self.session=registry
        self.server=HTTPServer(('127.0.0.1',port),Handler)
        self.thread=Thread(target=self.server.serve_forever,kwargs={'poll_interval':.1},daemon=True)
    def __enter__(self):self.thread.start();return self
    def __exit__(self,*args):
        self.session.close()
        self.server.shutdown();self.server.server_close();self.thread.join(3)
        if self.thread.is_alive():raise RuntimeError('Session API did not stop')
