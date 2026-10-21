"""Bounded public GMC2 HTTPS transport, shared by runtime and research CLI.

No account credentials, native analysis dependencies or persistent output.
"""
import ssl
import time
import urllib.error
import urllib.request

from .socks_route import SocksRoute

MAX_BODY = 2 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(request, *, route=None):
    expected = 'https://apis.netmarble.com/gc2/template-groups/netmarbles-v5/5.2.11?game=v5&country=G9&build=A&engine=unreal&market=nmp'
    if request['url'] != expected or request['method'] != 'GET' or dict(request['headers']).get('nmDeviceKey') != '':
        raise ValueError('Unsupported public GMC2 request')
    headers = dict(request['headers'])
    if any(name.lower() in ('accesstoken', 'playerid', 'authorization', 'cookie') for name in headers):
        raise ValueError('Public GMC2 probe cannot carry account credentials')
    headers.update({'User-Agent': 'PhoneExit-Vampir-Research/1', 'Accept-Encoding': 'identity'})
    if route is not None and not isinstance(route, SocksRoute): raise ValueError('Invalid explicit GMC2 route')
    opener = route.opener(NoRedirect()) if route else urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    deadline = time.monotonic() + 30
    try:
        response = opener.open(urllib.request.Request(request['url'], headers=headers), timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        if response.geturl() != request['url']:
            raise ValueError('Unexpected public GMC2 response URL')
        if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
            raise ValueError('Unsupported public GMC2 encoding')
        lengths = response.headers.get_all('Content-Length', [])
        if len(lengths) > 1 or (lengths and (not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0]) > 10)):
            raise ValueError('Invalid public GMC2 length')
        expected_size = int(lengths[0]) if lengths else None
        if expected_size is not None and expected_size > MAX_BODY:
            raise ValueError('Public GMC2 body exceeds budget')
        body = bytearray()
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError('Public GMC2 read budget exceeded')
            block = response.read1(min(65536, MAX_BODY + 1 - len(body)))
            if not block:
                break
            body.extend(block)
            if len(body) > MAX_BODY:
                raise ValueError('Public GMC2 body exceeds budget')
        if expected_size is not None and expected_size != len(body):
            raise ValueError('Incomplete public GMC2 body')
        selected = [(name, value) for name, value in response.headers.items() if name.lower() in
                    ('content-type', 'content-length', 'content-encoding', 'etag', 'deckey', 'date', 'last-modified')]
        status = response.code
    metadata = dict(status=status, headers=selected, tls_certificate_verification=True,
        redirects_followed=False, environment_proxy_used=False, account_credentials_sent=False,
        device_identity_sent=False, max_body_bytes=MAX_BODY, timeout_seconds=10, read_budget_seconds=30,
        request_header_overrides={'User-Agent': 'PhoneExit-Vampir-Research/1', 'Accept-Encoding': 'identity'},
        transport='Python urllib HTTPS, not native SDK transport replay')
    if route: metadata['socks5_loopback_port'] = route.port
    return bytes(body), metadata

