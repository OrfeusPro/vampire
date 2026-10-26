"""Owned loopback static server with shared caching for immutable UI snapshots."""
import argparse
import functools
import json
import os
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Timer


class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        if '/ui-prototype/snapshots/' in self.path and self.path.endswith(('.png', '.css', '.js', '.json', '.html')):
            self.send_header('Cache-Control', 'public, max-age=31536000, immutable')
        else:
            self.send_header('Cache-Control', 'no-cache')
        self.send_header('X-Content-Type-Options', 'nosniff')
        super().end_headers()


def serve(root,port,*,ready=None,lifetime=None):
    with ThreadingHTTPServer(('127.0.0.1',port),functools.partial(Handler,directory=str(root))) as server:
        timer=Timer(lifetime,server.shutdown) if lifetime else None
        if timer:timer.daemon=True;timer.start()
        if ready:ready(dict(status='ready',pid=os.getpid(),port=server.server_port,root=str(root)))
        else:print('Vampir UI: http://127.0.0.1:'+str(server.server_port)+'/maps/ui-prototype/index.html',flush=True)
        try:server.serve_forever(poll_interval=.1)
        except KeyboardInterrupt:pass
        finally:
            if timer:timer.cancel()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--port', type=int, default=17946)
    modes=parser.add_mutually_exclusive_group()
    modes.add_argument('--detached',action='store_true',help='Одноразовая задача Windows вне дерева Codex, срок до 24 часов')
    modes.add_argument('--scheduled-worker',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--lifetime-seconds',type=int,default=86400,help='Срок отдельного сервера: 1–86400 секунд')
    args = parser.parse_args()
    if not 1<=args.lifetime_seconds<=86400:parser.error('Неверный срок сервера')
    if args.detached or args.scheduled_worker:
        sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'vampir-shared'))
        from vampir_core.detached_worker import ready_channel,receive_handoff
        if args.scheduled_worker:
            ready=ready_channel();value=receive_handoff(sys.stdin.buffer)
            if set(value)!={'root','port','lifetime'} or type(value['port']) is not int or not 0<=value['port']<=65535:
                raise ValueError('Invalid UI server handoff')
            if type(value['lifetime']) is not int or not 1<=value['lifetime']<=86400:raise ValueError('Invalid UI server lifetime')
            serve(Path(value['root']),value['port'],ready=ready,lifetime=value['lifetime'])
        else:
            from vampir_core.scheduled_worker import launch_scheduled
            root=args.root.resolve(strict=True)
            if not root.is_dir():raise ValueError('UI directory required')
            value=launch_scheduled([sys.executable,'-X','utf8',str(Path(__file__).resolve()),'--scheduled-worker'],
                dict(root=str(root),port=args.port,lifetime=args.lifetime_seconds))
            print(json.dumps(value,ensure_ascii=False),flush=True)
    else:serve(args.root,args.port)
