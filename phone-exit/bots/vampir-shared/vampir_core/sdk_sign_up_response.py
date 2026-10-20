"""Strict first-player result; SDK SignUp is not a token-bearing SignIn."""
from dataclasses import dataclass, field
import json

from .sdk_sign_in_response import _object_pairs, _invalid_constant, _string


@dataclass(frozen=True, slots=True)
class SdkSignUpData:
    player_id: str = field(repr=False)


def parse_sdk_sign_up_response(*, status, body):
    if type(status) is not int or not 200 <= status <= 206:
        raise ValueError('SDK registration status rejected')
    if type(body) is not bytes or not 0 < len(body) <= 65536:
        raise ValueError('Invalid SDK registration body size')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_object_pairs, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Invalid SDK registration JSON') from None
    code = value.get('errorCode') if isinstance(value, dict) else None
    if not ((type(code) is int and code == 0) or (type(code) is str and code == '0')):
        raise ValueError('SDK registration requires explicit zero errorCode')
    result = value.get('resultData')
    info = result.get('playerInfo') if isinstance(result, dict) else None
    player = info.get('player') if isinstance(info, dict) else None
    if not isinstance(player, dict): raise ValueError('SDK registration player missing')
    return SdkSignUpData(_string(player.get('playerId'), required=True))
