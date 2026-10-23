"""Explicit read-only SDK Fetch plan, distinct from sign-in and player creation.

Current source: HEADLESS-RELEASE-FETCH-CONTRACT.md. Request construction is
statically recovered; strict JSON response policy is a local bounded subset.
"""
from dataclasses import dataclass
import json

from .nid_sdk_credential import NidSdkCredential
from .sdk_sign_in import _prepare_sdk_auth_context, _finish_sdk_auth_request
from .sdk_sign_in_response import _object_pairs, _invalid_constant


@dataclass(frozen=True, slots=True)
class SdkFetchSummary:
    result_object_present: bool
    game_session_ready: bool = False


def plan_nid_sdk_fetch(*, constants, credential, game_code, build_code,
                       nm_device_key, device_key, country_code, os_type):
    """POST v1/fetch-player: credential object and scope=channel only.

    Device/country inputs validate the same explicit runner context as sign-in;
    they are not inserted into this body. No cached SDK token is attached.
    """
    if not isinstance(credential, NidSdkCredential) or credential.channel_code != 33:
        raise ValueError('Fetch requires an explicit NID channel33 credential')
    base, _, headers = _prepare_sdk_auth_context(constants=constants, game_code=game_code,
        build_code=build_code, nm_device_key=nm_device_key, device_key=device_key,
        country_code=country_code, os_type=os_type, secret=credential.channel_access_token)
    payload = dict(credential=credential.as_object(), scope='channel')
    return _finish_sdk_auth_request(base, 'v1/fetch-player', payload, headers)


def parse_sdk_fetch_response(*, status, body):
    """Keep only a successful result-object marker; discard all identity data.

    Does not return a token/player ID or interpret a terms challenge. Nonzero
    results stop at the shared HTTP boundary; no sign-up or retry follows.
    """
    if type(status) is not int or not 200 <= status <= 206:
        raise ValueError('Fetch HTTP status rejected')
    if type(body) is not bytes or not 0 < len(body) <= 65536:
        raise ValueError('Invalid Fetch response size')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_object_pairs, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Invalid Fetch response JSON') from None
    if not isinstance(value, dict): raise ValueError('Fetch response must be an object')
    code = value.get('errorCode')
    if not ((type(code) is int and code == 0) or (type(code) is str and code == '0')):
        raise ValueError('Fetch requires explicit zero errorCode')
    # Native accepts optional resultData; this narrower diagnostic requires the
    # expected object and never exposes nested playerInfo/idpInfo.
    if not isinstance(value.get('resultData'), dict):
        raise ValueError('Fetch result object missing')
    return SdkFetchSummary(True)
