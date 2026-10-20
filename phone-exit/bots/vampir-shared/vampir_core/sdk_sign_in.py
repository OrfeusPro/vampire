"""Offline SDK sign-in request plan from verified caller body/header preparation.

Explicit endpoint/context only; no device identity acquisition, HTTP, persistence,
callback, SDK response or game session. Existing SDK token is separate from NID.
"""
from dataclasses import dataclass, field
import json
from urllib.parse import urlsplit

from .nid_sdk_credential import NidSdkCredential
from .sdk_config import append_sdk_path, lookup_sdk_url_value, select_sdk_build_code


@dataclass(frozen=True, slots=True)
class SdkSignInRequestPlan:
    url: str = field(repr=False)
    body: bytes = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    method: str = 'POST'


def plan_nid_sdk_sign_in(*, constants: dict, credential: NidSdkCredential, game_code: str,
                         build_code: int, nm_device_key: str, device_key: str, country_code: str,
                         os_type: str, player_id: str = '', existing_sdk_token: str = '') -> SdkSignInRequestPlan:
    """Prepare the email credential branch with explicitly supplied SDK context.

    Local printable ASCII/HTTPS budgets are stricter than native prefix checks.
    No defaults are inferred for BuildCode, game, platform, country or identity.
    playerId is omitted when empty; existing SDK token sets accessToken/authToken
    together and is never filled automatically with the provider access token.
    """
    if not isinstance(credential, NidSdkCredential) or credential.channel_code != 33:
        raise ValueError('Expected an explicit NID SDK channel33 credential')
    base, payload, headers = _prepare_sdk_auth_context(constants=constants, game_code=game_code,
        build_code=build_code, nm_device_key=nm_device_key, device_key=device_key, country_code=country_code,
        os_type=os_type, player_id=player_id, existing_sdk_token=existing_sdk_token, secret=credential.channel_access_token)
    if player_id:
        payload['playerId'] = player_id
    payload['credential'] = credential.as_object()
    return _finish_sdk_auth_request(base, 'v1/sign-in', payload, headers)


def _prepare_sdk_auth_context(*, constants, game_code, build_code, nm_device_key, device_key,
                              country_code, os_type, secret, player_id='', existing_sdk_token=''):
    """Shared, explicit device and default-header inputs for SDK auth methods."""
    values = (game_code, nm_device_key, device_key, country_code, os_type, player_id,
              existing_sdk_token, secret)
    if any(not isinstance(v, str) or len(v) > 8192 or any(not 32 <= ord(c) <= 126 for c in v) for v in values):
        raise ValueError('Invalid bounded ASCII SDK sign-in input')
    if any(not v for v in (game_code, nm_device_key, device_key, os_type, secret)):
        raise ValueError('SDK sign-in requires explicit nonempty identity/context')
    if len(country_code) != 2 or any(not 'A' <= c <= 'Z' for c in country_code):
        raise ValueError('Invalid explicit SDK sign-in country')
    build = select_sdk_build_code(build_code)
    base = lookup_sdk_url_value(constants, 'authUrl')
    try:
        if base is None or any(not 33 <= ord(c) <= 126 for c in base) or any(c in base for c in '\\?#'):
            raise ValueError
        parsed = urlsplit(base)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.port == 0):
            raise ValueError
    except ValueError:
        raise ValueError('Missing or unsupported HTTPS SDK auth endpoint') from None
    payload = dict(nmDeviceKey=nm_device_key, deviceKey=device_key, countryCode=country_code, os=os_type)
    headers = [('Content-Type', 'application/json'), ('Accept', 'application/json'),
               ('gameCode', game_code), ('buildCode', build)]
    if existing_sdk_token:
        headers += [('accessToken', existing_sdk_token), ('authToken', existing_sdk_token)]
    return base, payload, headers


def _finish_sdk_auth_request(base, suffix, payload, headers):
    body = json.dumps(payload, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    if len(body) > 32768:
        raise ValueError('SDK sign-in body exceeds local byte budget')
    if sum(len(k) + len(v) for k, v in headers) > 32768:
        raise ValueError('SDK sign-in headers exceed local byte budget')
    return SdkSignInRequestPlan(append_sdk_path(base, suffix), body, tuple(headers))


def plan_nid_sdk_sign_up(*, constants: dict, credential: NidSdkCredential, game_code: str,
                         build_code: int, nm_device_key: str, device_key: str, country_code: str,
                         os_type: str) -> SdkSignInRequestPlan:
    """Explicit first-player creation; never an automatic retry of sign-in.

    Verified SignUp body slices use the same four fields and optional credential
    as SignIn, without playerId. Header/POST factory is shared by the client.
    """
    plan = plan_nid_sdk_sign_in(constants=constants, credential=credential, game_code=game_code,
        build_code=build_code, nm_device_key=nm_device_key, device_key=device_key,
        country_code=country_code, os_type=os_type)
    return SdkSignInRequestPlan(append_sdk_path(lookup_sdk_url_value(constants, 'authUrl'), 'v1/sign-up'),
                                plan.body, plan.headers)
