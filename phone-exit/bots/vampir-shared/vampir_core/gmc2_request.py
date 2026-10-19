"""Offline GMC2 GET argument plan; no device identity creation or account IO.

Evidence: HEADLESS-GMC2-HEADERS.md. Native virtual calls are capture shims;
wire serialization/transport are not reproduced. HTTPS/ASCII/budgets below
are explicit local policy. An endpoint plan does not establish trust/readiness.
"""
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .sdk_config import select_sdk_build_code


@dataclass(frozen=True, slots=True)
class Gmc2RequestPlan:
    url: str = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    method: str = 'GET'


def _ascii(value, limit):
    if not isinstance(value, str) or len(value) > limit or any(not 32 <= ord(c) <= 126 for c in value):
        raise ValueError('Invalid GMC2 request field or local budget exceeded')
    return value


def plan_gmc2_get_request(*, url: str, service_code: str, game_code: str, build_code: int,
                          device_key: str, etag: str = '', player_id: str = '',
                          access_token: str = '') -> Gmc2RequestPlan:
    """Prepare explicit raw headers; no credentials are acquired or transmitted.

    Empty eTag is omitted. Nonempty access_token adds playerId/accessToken;
    player_id alone is omitted, matching the native access-token gate.
    Empty explicit required values are retained; no invented device identity.
    Local policy: HTTPS URL without userinfo/fragment, printable ASCII fields,
    each at most 4096 chars, total header name/value budget 32768 bytes.
    Native request body/default headers/encoding remain outside this model.
    """
    _ascii(url, 4096)
    try:
        parsed = urlsplit(url)
        valid = (url.startswith('https://') and bool(parsed.hostname) and not parsed.username
                 and not parsed.password and '@' not in parsed.netloc and not parsed.fragment
                 and ' ' not in url and parsed.port != 0)
    except ValueError:
        valid = False
    if not valid:
        raise ValueError('Invalid explicit GMC2 HTTPS URL')
    for value in (service_code, game_code, device_key, etag, player_id, access_token):
        _ascii(value, 4096)
    headers = [('Content-Type', 'application/json'), ('Accept', 'application/json'),
               ('serviceCode', service_code), ('gameCode', game_code),
               ('buildCode', select_sdk_build_code(build_code)), ('nmDeviceKey', device_key)]
    if etag:
        headers.append(('eTag', etag))
    if access_token:
        headers.extend((('playerId', player_id), ('accessToken', access_token)))
    if sum(len(name) + len(value) for name, value in headers) > 32768:
        raise ValueError('GMC2 headers exceed local budget')
    return Gmc2RequestPlan(url, tuple(headers))
