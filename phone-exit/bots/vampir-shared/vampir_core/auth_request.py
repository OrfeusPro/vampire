"""Offline SDK token-request plans, not email/password login or HTTP execution.

Evidence: HEADLESS-AUTH.md / HEADLESS-SDK-PATH.md. authTokenUrl is supplied
explicitly from SDK string constants, not inferred from client literals.
"""
from dataclasses import dataclass
from urllib.parse import urlsplit

from .sdk_config import append_sdk_path, lookup_sdk_url_value

_SAFE = frozenset(b'-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~')


def _escape_ascii(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError('Expected a nonempty bounded ASCII auth field')
    try:
        raw = value.encode('ascii')
    except UnicodeEncodeError:
        raise ValueError('Non-ASCII auth fields require separate native Unicode validation') from None
    if any(byte < 32 or byte == 127 for byte in raw):
        raise ValueError('Control characters in auth field')
    return ''.join(chr(byte) if byte in _SAFE else f'%{byte:02X}' for byte in raw)


@dataclass(frozen=True, slots=True, repr=False)
class TokenRequestPlan:
    body: bytes
    endpoint_key: str = 'authTokenUrl'
    relative_path: str = 'v2/access-token'
    method: str = 'POST'
    content_type: str = 'application/x-www-form-urlencoded'

    def __repr__(self):
        return 'TokenRequestPlan(POST authTokenUrl/v2/access-token, body=<redacted>)'


@dataclass(frozen=True, slots=True, repr=False)
class BoundTokenRequestPlan:
    url: str
    body: bytes
    method: str = 'POST'
    content_type: str = 'application/x-www-form-urlencoded'

    def __repr__(self):
        return 'BoundTokenRequestPlan(POST, url=<redacted>, body=<redacted>)'


def bind_token_request(plan: TokenRequestPlan, constants: dict) -> BoundTokenRequestPlan:
    """Bind an existing code/refresh plan to an explicit SDK base, without HTTP.

    Local policy rejects hostless bases, userinfo, query/fragment, backslashes,
    controls and invalid ports. This is stricter than the native prefix check;
    actual config acquisition, endpoint trust and authentication remain separate.
    """
    if not isinstance(plan, TokenRequestPlan) or not isinstance(plan.body, bytes) or len(plan.body) > 32768:
        raise ValueError('Expected a bounded token request plan')
    if (plan.endpoint_key, plan.relative_path, plan.method, plan.content_type) != (
            'authTokenUrl', 'v2/access-token', 'POST', 'application/x-www-form-urlencoded'):
        raise ValueError('Unsupported token request metadata')
    base = lookup_sdk_url_value(constants, plan.endpoint_key)
    if base is None:
        raise ValueError('Missing or unsupported SDK token endpoint')
    try:
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in base) or any(c in base for c in '\\?#'):
            raise ValueError
        parsed = urlsplit(base)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError
        parsed.port  # Validate syntax/range without resolving the host.
    except ValueError:
        raise ValueError('Unsupported SDK token base URL') from None
    return BoundTokenRequestPlan(append_sdk_path(base, plan.relative_path), plan.body)


def _plan(grant_type: str, client_id: str, device_key: str, field: str, secret: str) -> TokenRequestPlan:
    fields = [('grant_type', grant_type), ('client_id', client_id), ('device_key', device_key), (field, secret)]
    body = '&'.join(key+'='+_escape_ascii(value) for key, value in fields).encode('ascii')
    if len(body) > 32768:
        raise ValueError('Auth request exceeds local body budget')
    return TokenRequestPlan(body)


def plan_authorization_code(*, client_id: str, device_key: str, code: str) -> TokenRequestPlan:
    """Prepare the found authorization_code form without sending it."""
    return _plan('authorization_code', client_id, device_key, 'code', code)


def plan_refresh_token(*, client_id: str, device_key: str, refresh_token: str) -> TokenRequestPlan:
    """Prepare the found refresh_token form; does not validate token lifetime."""
    return _plan('refresh_token', client_id, device_key, 'refresh_token', refresh_token)
