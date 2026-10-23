"""One anonymous bounded terms GET; no redirects, credentials or acceptance."""
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlsplit

from .sdk_terms import (BasicTermsReadPlan, IndividualTermsReadPlan, plan_basic_terms_read,
                        plan_individual_terms_read, parse_basic_terms_summary, parse_individual_terms_summary)
from .socks_route import SocksRoute


class TermsReadError(RuntimeError):
    def __init__(self, kind):
        self.kind = kind
        super().__init__('Terms read failed: ' + kind)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args): return None


def _check_plan(plan):
    if type(plan) not in (BasicTermsReadPlan, IndividualTermsReadPlan) or plan.method != 'GET':
        raise ValueError('Explicit terms GET plan required')
    parts = urlsplit(plan.url)
    if parts.scheme != 'https' or parts.netloc != 'terms-api.netmarble.com' or parts.fragment:
        raise ValueError('Unsupported terms origin')
    path = parts.path.split('/')
    if len(path) not in (5, 6, 7) or path[:3] != ['', 'game', 'v2'] or path[4] != 'terms':
        raise ValueError('Unsupported terms path')
    query = parse_qs(parts.query, keep_blank_values=True, strict_parsing=True, max_num_fields=4)
    keys = {'country', 'locale', 'platform'}
    if type(plan) is IndividualTermsReadPlan: keys.add('termsType')
    if set(query) != keys or any(len(values) != 1 for values in query.values()):
        raise ValueError('Invalid terms query')
    inputs = dict(constants={'termsUrl': 'https://terms-api.netmarble.com'}, game_code=path[3],
                  country=query['country'][0], locale=query['locale'][0], platform=query['platform'][0])
    if type(plan) is BasicTermsReadPlan:
        if path[5:] not in ([], ['filtered', 'unique']): raise ValueError('Unsupported basic terms path')
        expected = plan_basic_terms_read(**inputs, filtered=bool(path[5:]))
    else:
        if path[5:] != ['terms_of_service_ko'] or query['termsType'] != ['I']:
            raise ValueError('Unsupported individual terms path/type')
        expected = plan_individual_terms_read(**inputs, terms_name='terms_of_service_ko')
    if plan.url != expected.url: raise ValueError('Terms query must match its canonical plan')


def execute_terms_read(plan, *, route=None, timeout=10, read_budget=30, max_response_bytes=524288,
                       _open=None, _clock=time.monotonic):
    _check_plan(plan)
    if route is not None and not isinstance(route, SocksRoute): raise ValueError('Invalid terms route')
    if (type(timeout) not in (int, float) or not 0 < timeout <= 30 or
            type(read_budget) not in (int, float) or not 0 < read_budget <= 60 or
            type(max_response_bytes) is not int or not 1 <= max_response_bytes <= 524288):
        raise ValueError('Invalid terms transport limits')
    if _open is None:
        opener = route.opener(_NoRedirect()) if route else urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())
        _open = opener.open
    request = urllib.request.Request(plan.url, method='GET', headers={
        'Accept': 'application/json', 'Accept-Encoding': 'identity', 'User-Agent': 'PhoneExit-Vampir/1'})
    try:
        with _open(request, timeout=timeout) as response:
            if type(response.status) is not int or not 200 <= response.status <= 206:
                raise TermsReadError('http_status')
            if response.headers.get('Content-Encoding', 'identity').lower() not in ('', 'identity'):
                raise TermsReadError('unsupported_encoding')
            declared = response.headers.get('Content-Length')
            if declared is not None:
                if type(declared) is not str or not declared.isascii() or not declared.isdigit() or len(declared) > 12:
                    raise TermsReadError('invalid_length')
                declared = int(declared)
                if declared > max_response_bytes: raise TermsReadError('body_too_large')
            start, body = _clock(), bytearray()
            while _clock() - start <= read_budget:
                chunk = response.read1(min(8192, max_response_bytes + 1 - len(body)))
                if not chunk: break
                body.extend(chunk)
                if len(body) > max_response_bytes: raise TermsReadError('body_too_large')
            else: raise TermsReadError('read_timeout')
            if declared is not None and len(body) != declared: raise TermsReadError('length_mismatch')
            parser = parse_basic_terms_summary if type(plan) is BasicTermsReadPlan else parse_individual_terms_summary
            return parser(status=response.status, body=bytes(body))
    except urllib.error.HTTPError as error:
        error.close()
        raise TermsReadError('http_status') from None
    except (OSError, urllib.error.URLError, TimeoutError):
        raise TermsReadError('transport') from None
