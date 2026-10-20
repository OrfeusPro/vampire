"""Bind only proven identity fields into otherwise explicit packet templates.

No registry/SDK IO, generated identity or account/expiry proof. Sources:
HEADLESS-VERSION-DEVICE-INPUT and HEADLESS-LOGIN-PACKET-FIELDS.
"""
from dataclasses import replace

from .version_packet import VersionPayload
from .login_packet import LoginPayload, _utf8
from .sdk_sign_in_response import SdkSignInData


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
