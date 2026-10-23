"""One bounded SDK sign-in POST; no redirects, retries or token persistence.

Request fields come from sdk_sign_in's source-bound plan. HTTP limits and error
policy are local; successful JSON decoding is not proof of a game session.
"""
import json
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .sdk_sign_in import SdkSignInRequestPlan
from .sdk_sign_in_response import parse_sdk_sign_in_response
from .sdk_sign_up_response import parse_sdk_sign_up_response
from .sdk_launcher_auth import parse_launcher_token_response
from .sdk_fetch import parse_sdk_fetch_response
from .socks_route import SocksRoute


class SdkSignInHttpError(RuntimeError):
    def __init__(self, kind, status=None, sdk_code=None):
        self.kind, self.status = kind, status
        self.sdk_code = sdk_code
        super().__init__('SDK sign-in failed: ' + kind)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _read_error_code(response, *, limit, budget, clock):
    """Keep only a bounded numeric SDK code; never retain server text or IDs."""
    if response.headers.get('Content-Encoding', 'identity').lower() not in ('', 'identity'): return None
    started, body = clock(), bytearray()
    try:
        while clock() - started <= budget:
            chunk = response.read1(min(8192, limit + 1 - len(body)))
            if not chunk: break
            body.extend(chunk)
            if len(body) > limit: return None
        else: return None
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result: raise ValueError('Duplicate key')
                result[key] = value
            return result
        value = json.loads(body.decode('utf-8'), object_pairs_hook=pairs)
        code = value.get('errorCode') if isinstance(value, dict) else None
        if type(code) is str and len(code) <= 11 and code.isascii():
            number = int(code)
            if str(number) != code: return None
            code = number
        return code if type(code) is int and -(2 ** 31) <= code < 2 ** 31 else None
    except (ValueError, UnicodeError, OSError, RecursionError): return None


def execute_sdk_sign_in(plan, *, expected_url, timeout=10, read_budget=30, max_response_bytes=65536,
                        route=None, _open=None, _clock=time.monotonic):
    return _execute_sdk_auth(plan, expected_url=expected_url, suffix='/v1/sign-in', timeout=timeout,
        read_budget=read_budget, max_response_bytes=max_response_bytes, _open=_open, _clock=_clock,
        parse_response=parse_sdk_sign_in_response, route=route)


def execute_sdk_sign_up(plan, *, expected_url, timeout=10, read_budget=30, max_response_bytes=65536,
                        route=None, _open=None, _clock=time.monotonic):
    """One explicit first-player POST; no fallback/retry or implicit creation."""
    return _execute_sdk_auth(plan, expected_url=expected_url, suffix='/v1/sign-up', timeout=timeout,
        read_budget=read_budget, max_response_bytes=max_response_bytes, _open=_open, _clock=_clock,
        parse_response=parse_sdk_sign_up_response, route=route)


def execute_sdk_fetch(plan, *, expected_url, timeout=10, read_budget=30, max_response_bytes=65536,
                      route=None, _open=None, _clock=time.monotonic):
    """One explicit read-only Fetch POST; no automatic continuation or creation."""
    return _execute_sdk_auth(plan, expected_url=expected_url, suffix='/v1/fetch-player', timeout=timeout,
        read_budget=read_budget, max_response_bytes=max_response_bytes, _open=_open, _clock=_clock,
        parse_response=parse_sdk_fetch_response, route=route)


def execute_launcher_token(plan, *, expected_url, timeout=10, read_budget=30, max_response_bytes=65536,
                           route=None, _open=None, _clock=time.monotonic):
    return _execute_sdk_auth(plan, expected_url=expected_url, suffix='/launcher/token', timeout=timeout,
        read_budget=read_budget, max_response_bytes=max_response_bytes, _open=_open, _clock=_clock,
        parse_response=parse_launcher_token_response, route=route)


def execute_launcher_sign_in(plan, *, expected_url, timeout=10, read_budget=30, max_response_bytes=65536,
                             route=None, _open=None, _clock=time.monotonic):
    return _execute_sdk_auth(plan, expected_url=expected_url, suffix='/launcher/sign-in', timeout=timeout,
        read_budget=read_budget, max_response_bytes=max_response_bytes, _open=_open, _clock=_clock,
        parse_response=parse_sdk_sign_in_response, route=route)


def _execute_sdk_auth(plan, *, expected_url, suffix, timeout, read_budget, max_response_bytes, _open, _clock, parse_response, route):
    """Execute a plan against the SAME explicitly trusted SDK endpoint.

    Parent owns provider origin/account/freshness and confirmation gates.
    HTTP failure, malformed reply or nonzero SDK result stops the attempt;
    no guessed challenge classification or automatic retries are performed.
    _open/_clock are deterministic transport fixtures used by unit tests.
    """
    if not isinstance(plan, SdkSignInRequestPlan) or plan.method != 'POST' or plan.url != expected_url:
        raise ValueError('SDK sign-in requires the bound expected endpoint')
    if route is not None and not isinstance(route, SocksRoute): raise ValueError('Invalid explicit SDK route')
    if (type(expected_url) is not str or not expected_url.startswith('https://')
            or '?' in expected_url or '#' in expected_url or not expected_url.endswith(suffix)):
        raise ValueError('Unsupported SDK sign-in endpoint')
    try:
        parts = urlsplit(expected_url)
        if not parts.hostname or parts.username is not None or parts.password is not None or parts.port == 0:
            raise ValueError
    except ValueError:
        raise ValueError('Unsupported SDK sign-in endpoint') from None
    if type(plan.body) is not bytes or not 1 <= len(plan.body) <= 32768:
        raise ValueError('Invalid SDK sign-in body size')
    if (type(timeout) not in (int, float) or not 0 < timeout <= 30 or
            type(read_budget) not in (int, float) or not 0 < read_budget <= 60 or
            type(max_response_bytes) is not int or not 1 <= max_response_bytes <= 65536):
        raise ValueError('Invalid SDK sign-in transport limits')
    try:
        headers = dict(plan.headers)
        if len(headers) != len(plan.headers) or any(type(k) is not str or type(v) is not str or
                any(ord(c) < 32 or ord(c) > 126 for c in k + v) for k, v in plan.headers):
            raise ValueError
        if sum(len(k) + len(v) for k, v in plan.headers) > 32768: raise ValueError
        if headers.get('Content-Type') != 'application/json' or headers.get('Accept') != 'application/json':
            raise ValueError
        request = urllib.request.Request(plan.url, data=plan.body, headers=headers, method='POST')
        request.add_header('Accept-Encoding', 'identity')
        request.add_header('User-Agent', 'PhoneExit-Vampir/1')
    except (ValueError, TypeError):
        raise ValueError('Invalid SDK sign-in request headers') from None
    if _open is None:
        opener = route.opener(_NoRedirect()) if route else urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())
        _open = opener.open
    try:
        with _open(request, timeout=timeout) as response:
            status = response.status
            if not 200 <= status <= 206: raise SdkSignInHttpError('http_status', status)
            if response.headers.get('Content-Encoding', 'identity').lower() not in ('', 'identity'):
                raise SdkSignInHttpError('unsupported_encoding', status)
            lengths = response.headers.get_all('Content-Length', [])
            declared = None
            if lengths:
                if len(lengths) != 1 or len(lengths[0]) > 10 or not lengths[0].isascii() or not lengths[0].isdigit():
                    raise SdkSignInHttpError('invalid_length', status)
                declared = int(lengths[0])
                if not 1 <= declared <= max_response_bytes: raise SdkSignInHttpError('response_limit', status)
            start = _clock()
            body = bytearray()
            while True:
                if _clock() - start > read_budget: raise SdkSignInHttpError('read_timeout', status)
                chunk = response.read1(min(8192, max_response_bytes + 1 - len(body)))
                if not chunk: break
                body.extend(chunk)
                if len(body) > max_response_bytes: raise SdkSignInHttpError('response_limit', status)
            if declared is not None and len(body) != declared: raise SdkSignInHttpError('truncated_response', status)
            try:
                return parse_response(status=status, body=bytes(body))
            except ValueError:
                raise SdkSignInHttpError('sdk_response_rejected', status) from None
    except urllib.error.HTTPError as exc:
        status = exc.code
        code = None
        if 400 <= status <= 599:
            code = _read_error_code(exc, limit=max_response_bytes, budget=read_budget, clock=_clock)
        exc.close()
        raise SdkSignInHttpError('http_status', status, code) from None
    except (OSError, urllib.error.URLError):
        raise SdkSignInHttpError('transport_error') from None
