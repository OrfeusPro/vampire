"""Owned loopback static server with shared caching for immutable UI snapshots."""
import argparse
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        if '/ui-prototype/snapshots/' in self.path and self.path.endswith(('.png', '.css', '.js', '.json', '.html')):
            self.send_header('Cache-Control', 'public, max-age=31536000, immutable')
        else:
            self.send_header('Cache-Control', 'no-cache')
        self.send_header('X-Content-Type-Options', 'nosniff')
        super().end_headers()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--port', type=int, default=17946)
    args = parser.parse_args()
    with ThreadingHTTPServer(('127.0.0.1', args.port), functools.partial(Handler, directory=str(args.root))) as server:
        print('Vampir UI: http://127.0.0.1:' + str(args.port) + '/maps/ui-prototype/index.html', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
