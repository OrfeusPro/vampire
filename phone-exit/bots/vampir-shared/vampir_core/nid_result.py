"""Validated NID email fields and a strict local callback boundary; no I/O.

Compiled channel mapper reproduced for bounded printable ASCII only. Result
validation deliberately requires canonical "0", unlike permissive native _wtoi.
These are provider credentials, not SDK/game session credentials.
"""
from dataclasses import dataclass, field
from types import MappingProxyType
from urllib.parse import urlsplit

from .sdk_percent import decode_sdk_percent_ascii

_CHANNELS = MappingProxyType(dict(signinwithapplekey=26, mailuserkey=20, epickey=31,
    facebookkey=1, gamecenterkey=6, googleidkey=29, googlekey=5, guest=100,
    netmarblekey=33, playstationkey=32, steamkey=30, twitterkey=12, xboxkey=34))


def channel_key_to_sdk_type(value: str) -> int:
    """Observed ASCII case-insensitive key mapping; no whitespace trimming.

    Unknown/empty printable ASCII keys map to 0. Non-ASCII, controls, non-string
    and more than 128 characters are rejected by local policy, without values.
    """
    if not isinstance(value, str) or len(value) > 128 or any(not 32 <= ord(c) <= 126 for c in value):
        raise ValueError('Invalid bounded ASCII NID channel key')
    return _CHANNELS.get(value.lower(), 0)


@dataclass(frozen=True, slots=True)
class NidEmailCredential:
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    netmarble_id: str = field(repr=False)
    joined_country_code: str = field(repr=False)
    channel_type: int = 20


def validate_nid_email_result_fields(fields: dict[str, str]) -> NidEmailCredential:
    """Validate explicitly decoded query fields, not an arbitrary callback URL.

    All six native lookup keys must exist; refreshToken may be empty. Optional
    web easyLoginToken/issueType are checked then discarded. No percent decoding,
    redirects, SDK settings mutation, channel linking or token exchange occurs.
    """
    required = frozenset(('resultCode', 'accessToken', 'refreshToken', 'channelKey',
                          'netmarbleId', 'joinedCountryCode'))
    optional = frozenset(('easyLoginToken', 'issueType'))
    if (not isinstance(fields, dict) or not required <= fields.keys()
            or fields.keys() - required - optional):
        raise ValueError('Missing or unsupported NID email result fields')
    if any(not isinstance(v, str) or len(v) > 8192 or any(not 32 <= ord(c) <= 126 for c in v)
           for v in fields.values()):
        raise ValueError('Invalid bounded ASCII NID email result value')
    if sum(len(v) for v in fields.values()) > 32768:
        raise ValueError('NID email result exceeds local byte budget')
    if fields['resultCode'] != '0':
        raise ValueError('NID email result is not canonical success')
    if channel_key_to_sdk_type(fields['channelKey']) != 20:
        raise ValueError('NID email result has a different or unknown channel')
    country = fields['joinedCountryCode']
    if not fields['accessToken'] or not fields['netmarbleId'] or len(country) != 2 or any(not 'A' <= c <= 'Z' for c in country):
        raise ValueError('Invalid NID email credential fields')
    return NidEmailCredential(fields['accessToken'], fields['refreshToken'], fields['netmarbleId'], country)


def parse_nid_email_callback(url: str, *, expected_game_code: str) -> NidEmailCredential:
    """Local callback boundary for the explicitly expected game/result route.

    Mirrors observed whole-query percent decoding before splitting fields,
    preserving plus signs. Rejects duplicates, unsupported fields and malformed
    escapes. This checks routing only: no nonce, signature, browser provenance,
    server token validity or active sign-in state is established by a URL.
    Full native URI/parser/map behavior is not reproduced by this local policy.
    """
    if (not isinstance(expected_game_code, str) or not 1 <= len(expected_game_code) <= 64
            or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in expected_game_code)):
        raise ValueError('Invalid explicit NID game scope')
    if (not isinstance(url, str) or len(url) > 32768 or '\\' in url or '#' in url
            or any(not 33 <= ord(c) <= 126 for c in url)):
        raise ValueError('Invalid bounded ASCII NID callback URL')
    try:
        parts = urlsplit(url)
        scheme = 'nm' + expected_game_code
        if (not url.startswith(scheme + '://') or parts.scheme != scheme or parts.netloc != 'nmidprovider'
                or parts.path != '/result' or parts.fragment or not parts.query):
            raise ValueError
    except ValueError:
        raise ValueError('NID callback route differs from explicit game scope') from None
    if '%26' in parts.query.lower():
        raise ValueError('Ambiguous encoded NID query separator')
    decoded = decode_sdk_percent_ascii(parts.query)
    segments = decoded.split('&')
    if len(segments) > 8:
        raise ValueError('NID callback has too many fields')
    fields = {}
    for segment in segments:
        name, separator, value = segment.partition('=')
        if not separator or not name or name in fields:
            raise ValueError('Malformed or duplicate NID callback field')
        fields[name] = value
    return validate_nid_email_result_fields(fields)
