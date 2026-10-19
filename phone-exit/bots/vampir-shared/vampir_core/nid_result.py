"""Validated decoded NID email result fields; no URL parser, persistence or I/O.

Compiled channel mapper reproduced for bounded printable ASCII only. Result
validation deliberately requires canonical "0", unlike permissive native _wtoi.
These are provider credentials, not SDK/game session credentials.
"""
from dataclasses import dataclass, field
from types import MappingProxyType

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
