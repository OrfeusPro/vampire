"""Bind proven initial NID context to its explicit public SDK endpoint.

Printable ASCII subset of native value encoding, reusing auth_request escape.
Tuple order is deterministic; byte identity of Unreal map iteration is not
claimed. No browser, credential acquisition or callback registration.
"""
from dataclasses import dataclass, field

from .auth_request import _escape_ascii
from .nid_web_context import NidWebContext
from .sdk_config import lookup_sdk_url_value

_KEYS = ('gameCode', 'buildCode', 'countryCode', 'language', 'os', 'nmDeviceKey',
         'deviceKey', 'osVersion', 'clientId', 'nidV', 'webViewType', 'authType')


@dataclass(frozen=True, slots=True)
class NidWebUrl:
    url: str = field(repr=False)


def bind_nid_web_url(context, *, constants, max_url_size):
    """Build one initial signin URL; keep it out of logs and shared artifacts.

    Endpoint scope is the observed members.netmarble.com/auth page. An updated
    endpoint requires source validation rather than silently sending device
    fields to a different host. No cached tokens or linking modes are supported.
    """
    if not isinstance(context, NidWebContext): raise TypeError('Expected NID web context')
    if type(max_url_size) is not int or not 1 <= max_url_size <= 131072:
        raise ValueError('Expected explicit NID URL byte budget')
    pairs = context.parameters
    if type(pairs) is not tuple or len(pairs) != len(_KEYS):
        raise ValueError('Unsupported NID parameter set')
    for pair, key in zip(pairs, _KEYS):
        if type(pair) is not tuple or len(pair) != 2 or pair[0] != key or type(pair[1]) is not str:
            raise ValueError('Malformed NID parameter set')
    values = dict(pairs)
    if values['nidV'] != '3' or values['authType'] != 'signin' or values['webViewType'] not in ('sdk', 'steam', 'epic', 'xbox'):
        raise ValueError('Unsupported NID sign-in mode')
    if not all(values[key] for key in ('gameCode', 'clientId', 'nmDeviceKey', 'deviceKey')):
        raise ValueError('Required NID parameter is empty')
    base = lookup_sdk_url_value(constants, 'authWebViewUrl')
    if base != 'https://members.netmarble.com/auth':
        raise ValueError('Unsupported NID auth endpoint')
    # Existing verified auth encoder uses %20 and uppercase hex, never '+'.
    query = '&'.join(key + '=' + (_escape_ascii(value) if value else '') for key, value in pairs)
    url = base + '?' + query
    if len(url) > max_url_size: raise BufferError('NID URL exceeds local byte budget')
    return NidWebUrl(url)
