"""Attach/reload local observational code while the separate game owner runs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from urllib.parse import urlencode
from urllib.request import build_opener,ProxyHandler,Request
from urllib.error import URLError

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'vampir-shared'))
from vampir_core.live_diagnostics import TRACE_IDS


def evaluate(handler,payload,*,timeout=2):
    source=handler.read_bytes()
    if len(source)>1048576:raise ValueError('Handler source limit')
    revision=hashlib.sha256(source).hexdigest()
    try:
        result=subprocess.run([sys.executable,'-B',str(HERE/'live-observer-worker.py'),str(handler)],
            input=json.dumps(payload,allow_nan=False).encode(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            timeout=timeout,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if result.returncode or len(result.stdout)>16384:raise ValueError('Worker output limit or failure')
        value=json.loads(result.stdout)
        if type(value) is not dict or set(value)!={'revision','values','error'} or value['revision']!=revision:raise ValueError('Worker revision changed')
        if type(value['values']) is not dict:raise ValueError('Invalid worker values')
        return value
    except subprocess.TimeoutExpired:return dict(revision=revision,values={},error='HandlerTimeout')
    except (ValueError,UnicodeError):return dict(revision=revision,values={},error='HandlerFailed')


def watch(*,bot,session,handler,port=17947,packet_ids=()):
    if any(not re.fullmatch('[a-zA-Z0-9_-]{1,48}',v) for v in (bot,session)):raise ValueError('Explicit bot/session required')
    if not 1<=port<=65535 or not set(packet_ids)<=TRACE_IDS:raise ValueError('Invalid port or packet allowlist')
    handler=handler.resolve(strict=True)
    if handler.suffix!='.py':raise ValueError('Local Python handler required')
    base='http://127.0.0.1:'+str(port)+'/bots/'+bot
    opener=build_opener(ProxyHandler({}));token=None;lease=secrets.token_hex(16)
    def request(action,value=None,query=None):
        data=None if value is None else json.dumps(dict(bot_id=bot,session_id=session,**value),allow_nan=False).encode()
        headers={'Content-Type':'application/json'}
        if token:headers['X-Session-Token']=token
        url=base+'/'+action+('?' + urlencode(query) if query else '')
        with opener.open(Request(url,data=data,headers=headers),timeout=3) as response:
            raw=response.read(262145)
            if len(raw)>262144:raise ValueError('API response limit')
            return json.loads(raw)
    control=request('control')
    if control.get('bot_id')!=bot or control.get('session_id')!=session:raise ValueError('Session changed')
    token=control['token'];cursor=0;sample_cursor=0;renew=0;previous={};last=None;trace_owned=False
    try:
        while True:
            started=time.monotonic()
            state=request('state')
            if state.get('bot_id')!=bot or state.get('session_id')!=session:raise ValueError('Session changed')
            if state['state']=='disconnected':break
            events=request('events',query=dict(session=session,after=cursor))
            samples=dict(samples=[],cursor=sample_cursor,gap=False)
            if packet_ids:
                if started>=renew:
                    request('trace',dict(lease=lease,packet_ids=list(packet_ids)));trace_owned=True;renew=started+20
                samples=request('samples',query=dict(session=session,after=sample_cursor,lease=lease))
            value=evaluate(handler,dict(state=state,events=events,samples=samples,previous=previous))
            request('analysis',value)
            cursor=events['cursor'];sample_cursor=samples['cursor']
            if value['error'] is None:previous=value['values']
            if value!=last:print(json.dumps(dict(bot_id=bot,session_id=session,**value),ensure_ascii=False),flush=True);last=value
            time.sleep(max(0,1-(time.monotonic()-started)))
    finally:
        if trace_owned:
            try:request('trace',dict(lease=lease,packet_ids=[]))
            except Exception:pass  # Lease also expires after 60 s without renewal.


if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Живой разбор без перезапуска игрового соединения. Ctrl+C закрывает только наблюдатель.')
    parser.add_argument('--bot',required=True);parser.add_argument('--session',required=True)
    parser.add_argument('--handler',required=True,type=Path);parser.add_argument('--port',type=int,default=17947)
    parser.add_argument('--trace-packet',type=int,action='append',default=[],choices=sorted(TRACE_IDS))
    args=parser.parse_args()
    try:watch(bot=args.bot,session=args.session,handler=args.handler,port=args.port,packet_ids=args.trace_packet)
    except KeyboardInterrupt:print('Наблюдатель остановлен; игровая сессия продолжает работу.')
    except (URLError,OSError,ValueError) as error:
        print('Наблюдатель завершён: сервис недоступен или входные данные изменились ('+type(error).__name__+').',file=sys.stderr)
        sys.exit(1)
