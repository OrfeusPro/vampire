"""Bind only proven identity fields into otherwise explicit packet templates.

No registry/SDK IO, generated identity or account/expiry proof. Sources:
HEADLESS-VERSION-DEVICE-INPUT and HEADLESS-LOGIN-PACKET-FIELDS.
"""
from dataclasses import replace

from .version_packet import VersionPayload
from .login_packet import LoginPayload, _utf8
from .sdk_sign_in_response import SdkSignInData
from .device_registry import DeviceBinding
from .lobby_login_result import LobbyLoginResultBody
from .lobby_packets import LobbyLoginPayload


def _bind(strings, index, value):
    if type(value) is not str or not value:
        raise ValueError('Identity field must be nonempty text')
    _utf8(value)
    if strings[index] not in ('', value):
        raise ValueError('Packet template has conflicting identity context')
    output = list(strings)
    output[index] = value
    return tuple(output)


def bind_nm_device_key(version, login, *, nm_device_key):
    """Version+0x48 / Login+0x78 share the NM key; preserve original text.

    Existing unequal values are rejected, preventing silent mixing of packet
    templates from different devices. Other fields and keys are not inferred.
    """
    if not isinstance(version, VersionPayload) or not isinstance(login, LoginPayload):
        raise TypeError('Expected explicit Version and Login templates')
    version_strings = _bind(version.strings, 3, nm_device_key)
    login_strings = _bind(login.strings, 6, nm_device_key)
    return replace(version, strings=version_strings), replace(login, strings=login_strings)


def bind_game_app_version(version, login, *, app_version):
    """One explicit NetworkSetting AppVersion -> Version+0x10 / Login+0x40.

    Does not choose a config layer or claim the game's active cache. Sources:
    HEADLESS-CDN-CONFIG, HEADLESS-CONNECTED-VERSION-PACKET, HEADLESS-LOGIN-PACKET-FIELDS.
    """
    if not isinstance(version, VersionPayload) or not isinstance(login, LoginPayload):
        raise TypeError('Expected explicit Version and Login templates')
    return (replace(version, strings=_bind(version.strings, 0, app_version)),
        replace(login, strings=_bind(login.strings, 3, app_version)))


def bind_sdk_login_fields(login, *, sdk_data, netmarble_id):
    """SDK response accessToken -> Login+0xa0; separate NID -> Login+0x30.

    playerId is not substituted for Netmarble ID. Caller must establish origin,
    account binding and freshness of sdk_data; the parser alone cannot do so.
    """
    if not isinstance(login, LoginPayload) or not isinstance(sdk_data, SdkSignInData):
        raise TypeError('Expected Login template and parsed SDK data')
    strings = _bind(login.strings, 2, netmarble_id)
    strings = _bind(strings, 8, sdk_data.access_token)
    return replace(login, strings=strings)


def bind_lobby_login_fields(login, *, lobby_result):
    """Lobby success +20/+30 -> wrapper +f0/+e0 -> game Login +10/+20.

    The caller owns connection/account provenance; a parsed result cannot prove
    it. No server selection or game Login transition is performed here.
    """
    if not isinstance(login, LoginPayload) or not isinstance(lobby_result, LobbyLoginResultBody):
        raise TypeError('Expected game Login template and separate lobby result')
    if lobby_result.result_code != 0:
        raise ValueError('Lobby login did not succeed')
    strings = _bind(login.strings, 0, lobby_result.strings[0])
    strings = _bind(strings, 1, lobby_result.strings[1])
    return replace(login, strings=strings)


def bind_lobby_sdk_fields(login, *, sdk_data, netmarble_id, nm_device_key, joined_country_code):
    """Bind lobby +18/+28/+38/+48/+58; keep +70 metadata and all numbers explicit.

    Sources: Lobby_LoginPrepare, SDK GetPlayerId/token accessors and NID
    UserInfo+170 -> I_JoinedCountryCode. Caller establishes freshness/account
    provenance; SDK parsing alone is not authentication or a country observation.
    """
    if not isinstance(login, LobbyLoginPayload) or not isinstance(sdk_data, SdkSignInData):
        raise TypeError('Expected separate lobby Login and parsed SDK data')
    strings = login.strings
    for index, value in enumerate((sdk_data.player_id, sdk_data.access_token, nm_device_key,
            joined_country_code, netmarble_id)):
        strings = _bind(strings, index, value)
    return replace(login, strings=strings)


def prepare_registered_login(version, login, *, binding, sdk_data, netmarble_id):
    """Prepare proven fields for an explicitly selected observed device profile.

    required confirmation blocks attempts; unknown allows the initial attempt
    that may produce a challenge. No network, challenge recognition or proof
    that supplied SDK data belong to this account. Other context is explicit.
    """
    if not isinstance(binding, DeviceBinding) or binding.kind != 'real':
        raise ValueError('Login requires an observed device profile')
    if binding.confirmation == 'required':
        raise PermissionError('Device confirmation is required before another login attempt')
    if binding.confirmation not in ('unknown', 'confirmed'):
        raise ValueError('Unsupported device confirmation state')
    if not binding.identity_recorded or not binding.nid_identity_recorded:
        raise ValueError('Login device profile is incomplete')
    version, login = bind_nm_device_key(version, login, nm_device_key=binding.nm_device_key)
    return version, bind_sdk_login_fields(login, sdk_data=sdk_data, netmarble_id=netmarble_id)
