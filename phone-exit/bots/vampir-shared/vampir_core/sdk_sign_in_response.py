"""Strict offline extraction of SDK sign-in data, not authentication/session proof."""
from dataclasses import dataclass, field
import json


@dataclass(frozen=True)
class SdkSignInData:
    access_token: str = field(repr=False)
    player_id: str = field(repr=False)
    game_region: str | None = field(repr=False)
    joined_country_code: str | None = field(repr=False)
    idp_info_count: int | None


def _object_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate SDK response key')
        value[key] = item
    return value


def _invalid_constant(value):
    raise ValueError('Nonfinite SDK response value')


def _string(value, *, required):
    if not isinstance(value, str) or len(value) > 8192 or (required and not value):
        raise ValueError('Invalid SDK response text field')
    if any(not 32 <= ord(c) <= 126 for c in value):
        raise ValueError('Unsupported SDK response text encoding')
    return value


def parse_sdk_sign_in_response(*, status: int, body: bytes) -> SdkSignInData:
    """Require explicit zero errorCode and fresh nonempty SDK token/player ID.

    Local policy is stricter than native optional-field/CRT behavior. Never
    substitute a provider token or previous account state. HTTP transport,
    origin, request binding, expiry and server acceptance are outside this API.
    """
    if type(status) is not int or not 200 <= status <= 206:
        raise ValueError('SDK response status rejected')
    if not isinstance(body, bytes) or not 0 < len(body) <= 65536:
        raise ValueError('Invalid SDK response body size')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_object_pairs, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Invalid SDK response JSON') from None
    if not isinstance(value, dict):
        raise ValueError('SDK response must be an object')
    code = value.get('errorCode')
    if not ((type(code) is int and code == 0) or (type(code) is str and code == '0')):
        raise ValueError('SDK response requires explicit canonical zero errorCode')
    result = value.get('resultData')
    info = result.get('playerInfo') if isinstance(result, dict) else None
    player = info.get('player') if isinstance(info, dict) else None
    if not isinstance(player, dict):
        raise ValueError('SDK response player data missing')
    token = _string(result.get('accessToken'), required=True)
    player_id = _string(player.get('playerId'), required=True)
    region = _string(player['gameRegion'], required=False) if 'gameRegion' in player else None
    country = _string(player['joinedCountryCode'], required=False) if 'joinedCountryCode' in player else None
    count = None
    if 'idpInfo' in info:
        providers = info['idpInfo']
        if not isinstance(providers, list) or len(providers) > 64:
            raise ValueError('Invalid SDK identity provider array')
        count = len(providers)
    # Raw idpInfo can include identity details; retain only its count until mapped.
    return SdkSignInData(token, player_id, region, country, count)
