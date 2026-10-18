"""Offline SDK token-request plans, not email/password login or HTTP execution.

Evidence: HEADLESS-AUTH.md. The server base URL is deliberately unresolved:
authTokenUrl must come from the verified current SDK configuration.
"""
from dataclasses import dataclass

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
