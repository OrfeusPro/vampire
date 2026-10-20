"""Explicit loopback SOCKS5 route; remote DNS and verified end-to-end TLS."""
from dataclasses import dataclass
import http.client
import socket
import ssl
import urllib.error
import urllib.request


@dataclass(frozen=True, slots=True)
class SocksRoute:
    port: int

    def __post_init__(self):
        if type(self.port) is not int or not 1024 <= self.port <= 65535:
            raise ValueError('Invalid local SOCKS port')

    @property
    def browser_arguments(self):
        return '--proxy-server=socks5://127.0.0.1:' + str(self.port) + ' --disable-quic'

    def connect(self, host, port, *, timeout=10):
        # Import only when SOCKS is explicitly selected. Never monkeypatch sockets.
        import socks
        if type(host) is not str or not host or len(host) > 253 or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('Invalid SOCKS target')
        if type(timeout) not in (int, float) or not 0 < timeout <= 60:
            raise ValueError('Invalid SOCKS timeout')
        connection = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            connection.set_proxy(socks.SOCKS5, '127.0.0.1', self.port, rdns=True)
            connection.settimeout(timeout)
            connection.connect((host, port))
            return connection
        except BaseException:
            connection.close()
            raise

    def https_handler(self):
        route = self
        class Connection(http.client.HTTPSConnection):
            def connect(self):
                if self._tunnel_host: raise OSError('HTTP proxy chaining is not supported')
                raw = route.connect(self.host, self.port, timeout=self.timeout)
                try:
                    self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                except BaseException:
                    raw.close()
                    raise
        class Handler(urllib.request.HTTPSHandler):
            def https_open(self, request):
                return self.do_open(Connection, request, context=self._context)
        return Handler(context=ssl.create_default_context())

    def opener(self, redirect_handler):
        # Ignore OS/environment proxy settings. No alternate direct handler.
        class RejectHTTP(urllib.request.HTTPHandler):
            def http_open(self, request):
                raise urllib.error.URLError('HTTPS is required for the selected SOCKS route')
        return urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                            self.https_handler(), RejectHTTP(), redirect_handler)
