"""Explicit launcher auth requests; opaque token, no inferred launcher lifecycle.

Sources: HEADLESS-LAUNCHER-{AUTH-CONTEXT,TOKEN-CONTEXT,CHANNEL-ROUTING}.
NID credential33 remains distinct from the launcherToken request header.
"""
from dataclasses import dataclass, field
import json

from .nid_sdk_credential import NidSdkCredential
from .sdk_sign_in import _prepare_sdk_auth_context, _finish_sdk_auth_request
from .sdk_sign_in_response import _object_pairs, _invalid_constant, _string


@dataclass(frozen=True, slots=True)
class LauncherToken:
    value: str = field(repr=False)


def plan_nid_launcher_token(*, constants, credential, game_code, build_code,
                            nm_device_key, device_key, country_code, os_type, existing_sdk_token=''):
    """GetLauncherToken(33): NID GetObject + gameCode/buildCode inside credential.

    No ordinary SDK sign-in or sign-up is performed implicitly. The caller owns
    provider account/freshness, device provenance and the selected SDK endpoint.
    """
    if not isinstance(credential, NidSdkCredential) or credential.channel_code != 33:
        raise ValueError('Expected an explicit NID SDK channel33 credential')
    base, payload, headers = _prepare_sdk_auth_context(constants=constants, game_code=game_code,
        build_code=build_code, nm_device_key=nm_device_key, device_key=device_key, country_code=country_code,
        os_type=os_type, existing_sdk_token=existing_sdk_token, secret=credential.channel_access_token)
    payload['credential'] = dict(credential.as_object(), gameCode=game_code, buildCode=dict(headers)['buildCode'])
    return _finish_sdk_auth_request(base, 'launcher/token', payload, headers)


def plan_launcher_sign_in(*, constants, launcher_token, game_code, build_code,
                          nm_device_key, device_key, country_code, os_type, existing_sdk_token=''):
    """Four device fields, launcherToken custom header, shared SDK default headers.

    Neither channelCode200 nor channelAccessToken is inserted into this body.
    The token is passed unchanged; JWT contents/signature are not interpreted.
    """
    if not isinstance(launcher_token, LauncherToken):
        raise ValueError('Expected an explicit launcher token')
    base, payload, headers = _prepare_sdk_auth_context(constants=constants, game_code=game_code,
        build_code=build_code, nm_device_key=nm_device_key, device_key=device_key, country_code=country_code,
        os_type=os_type, existing_sdk_token=existing_sdk_token, secret=launcher_token.value)
    headers.append(('launcherToken', launcher_token.value))
    return _finish_sdk_auth_request(base, 'launcher/sign-in', payload, headers)


def parse_launcher_token_response(*, status, body):
    """Require zero errorCode and fresh nonempty string resultData.

    Local bounded ASCII policy is stricter than native getters. This is not
    JWT validation, an account-binding check or proof of a game session.
    """
    if type(status) is not int or not 200 <= status <= 206:
        raise ValueError('Launcher token HTTP status rejected')
    if type(body) is not bytes or not 0 < len(body) <= 65536:
        raise ValueError('Invalid launcher token response size')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_object_pairs, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Invalid launcher token JSON') from None
    if not isinstance(value, dict):
        raise ValueError('Launcher token response must be an object')
    code = value.get('errorCode')
    if not ((type(code) is int and code == 0) or (type(code) is str and code == '0')):
        raise ValueError('Launcher token response requires explicit zero errorCode')
    return LauncherToken(_string(value.get('resultData'), required=True))
