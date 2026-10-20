"""Proven NID sign-in web context, before URL encoding/browser delivery.

HEADLESS-NID-WEB-CONTEXT: ten base pairs and native webViewType mapping.
All settings explicit; no URL query encoder, browser or credential acquisition.
"""
from dataclasses import dataclass, field

from .device_registry import DeviceBinding
from .sdk_config import select_sdk_build_code


@dataclass(frozen=True, slots=True)
class NidWebContext:
    parameters: tuple[tuple[str, str], ...] = field(repr=False)


def nid_webview_type(raw_type):
    if type(raw_type) is not int or not 0 <= raw_type <= 255:
        raise ValueError('Expected explicit NID webview type byte')
    return {30: 'steam', 31: 'epic', 34: 'xbox'}.get(raw_type, 'sdk')


def prepare_nid_sign_in_context(*, binding, game_code, build_code, country_code,
                                language, os_type, os_version, client_id, raw_webview_type):
    """Prepare the initial signin branch, without cached accessToken fields.

    deviceKey uses NID identity, NOT the separate SDK sign-in DeviceKey.
    Source class supplies settings; caller must establish their active values.
    required confirmation prevents a new attempt; unknown can make the first.
    """
    if not isinstance(binding, DeviceBinding) or binding.kind != 'real':
        raise ValueError('NID context requires an observed device profile')
    if binding.confirmation == 'required':
        raise PermissionError('Device confirmation is required before another sign-in attempt')
    if binding.confirmation not in ('unknown', 'confirmed') or not binding.identity_recorded or not binding.nid_identity_recorded:
        raise ValueError('NID device context is incomplete')
    values = (game_code, country_code, language, os_type, binding.nm_device_key,
              binding.nid_device_key, os_version, client_id)
    for value in values:
        if type(value) is not str or len(value) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('Invalid NID context text')
        try: value.encode('utf-8')
        except UnicodeEncodeError: raise ValueError('Invalid NID context Unicode') from None
    if not all((game_code, client_id, binding.nm_device_key, binding.nid_device_key)):
        raise ValueError('Required NID context is empty')
    pairs = tuple(zip(('gameCode', 'buildCode', 'countryCode', 'language', 'os', 'nmDeviceKey',
                       'deviceKey', 'osVersion', 'clientId', 'nidV'),
                      (game_code, select_sdk_build_code(build_code), country_code, language, os_type,
                       binding.nm_device_key, binding.nid_device_key, os_version, client_id, '3')))
    pairs += (('webViewType', nid_webview_type(raw_webview_type)), ('authType', 'signin'))
    if sum(len(k.encode('utf-8')) + len(v.encode('utf-8')) for k, v in pairs) > 32768:
        raise BufferError('NID context exceeds local byte budget')
    return NidWebContext(pairs)
