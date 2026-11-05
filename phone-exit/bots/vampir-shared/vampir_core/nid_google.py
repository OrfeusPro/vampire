"""NID's Google result contains a Netmarble token, not the Google ID token."""
from dataclasses import dataclass, field
from .nid_result import parse_nid_callback_fields, channel_key_to_sdk_type


@dataclass(frozen=True, slots=True)
class NidGoogleCredential:
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    netmarble_id: str = field(repr=False)
    joined_country_code: str = field(repr=False)
    channel_type: int = field(default=29, init=False)


def validate_nid_google_result_fields(fields):
    required = {'resultCode', 'accessToken', 'refreshToken', 'channelKey', 'netmarbleId', 'joinedCountryCode'}
    if type(fields) is not dict or not required <= fields.keys() or fields.keys() - required - {'easyLoginToken', 'issueType'}:
        raise ValueError('Missing or unsupported NID Google fields')
    if any(type(v) is not str or len(v) > 8192 or any(not 32 <= ord(c) <= 126 for c in v) for v in fields.values()):
        raise ValueError('Invalid NID Google value')
    if sum(map(len, fields.values())) > 32768 or fields['resultCode'] != '0':
        raise ValueError('NID Google result is not accepted success')
    if channel_key_to_sdk_type(fields['channelKey']) != 29:
        raise ValueError('NID Google result has a different provider')
    country = fields['joinedCountryCode']
    if not fields['accessToken'] or not fields['netmarbleId'] or len(country) != 2 or any(not 'A' <= c <= 'Z' for c in country):
        raise ValueError('Invalid NID Google credential fields')
    return NidGoogleCredential(fields['accessToken'], fields['refreshToken'], fields['netmarbleId'], country)


def parse_nid_google_callback(url, *, expected_game_code):
    return validate_nid_google_result_fields(parse_nid_callback_fields(url, expected_game_code=expected_game_code))
