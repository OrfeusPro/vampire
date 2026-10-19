"""Offline public GMC2 success envelope -> isolated SDK string constants.

Uses existing bounded JSON, unit XOR, RSA chunk/list and map-merge primitives.
This is strict local response policy, not full native callback execution.
"""
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from .cdn_config import _load_object  # Reuse shared bounded JSON policy, no CDN AES fallback.
from .gmc2_decode import MAX_XOR_BYTES, xor_gmc2_utf16_units
from .sdk_config import merge_sdk_string_constants
from .sdk_secret import decode_sdk_secret_constants


@dataclass(frozen=True, slots=True)
class SdkConfiguration:
    constants: Mapping[str, str] = field(repr=False)
    normal_count: int
    secret_count: int


def decode_gmc2_configuration(body: bytes, headers: list | tuple) -> SdkConfiguration:
    """Decode a complete status-200 body with one explicit DECKEY header.

    Caller verifies HTTP status, framing, TLS and URL trust before this call.
    Local policy requires errorCode integer 0, resultData object and both
    encrypted string fields. DECKEY: one printable ASCII value <=4096 chars.
    UTF8 body/plaintext JSON have the existing bounded duplicate/nonfinite/
    nesting/Unicode rules. Return only a read-only merged map, not the key.
    No account session, endpoint readiness or native callback acceptance claim.
    """
    try:
        if not isinstance(body, bytes) or len(body) > MAX_XOR_BYTES:
            raise ValueError
        if not isinstance(headers, (list, tuple)) or len(headers) > 256:
            raise ValueError
        keys = []
        for pair in headers:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2 or not all(isinstance(v, str) for v in pair):
                raise ValueError
            name, value = pair
            if name.lower() == 'deckey':
                keys.append(value)
        if len(keys) != 1 or not 0 < len(keys[0]) <= 4096 or any(not 33 <= ord(c) <= 126 for c in keys[0]):
            raise ValueError
        key = keys[0]
        # Encrypted unit strings legitimately contain escaped NUL; plaintext
        # parsing retains the original strict no-NUL policy below.
        document = _load_object(body.decode('utf-8-sig', 'strict'), allow_nul_strings=True)
        if type(document.get('errorCode')) is not int or document['errorCode'] != 0 or not isinstance(document.get('resultData'), dict):
            raise ValueError
        result = document['resultData']
        def decrypt_field(name):
            text = result.get(name)
            if not isinstance(text, str) or len(text) > MAX_XOR_BYTES // 2:
                raise ValueError
            # JSON parsing has already unescaped these fields. Never unescape twice.
            units = xor_gmc2_utf16_units(text.encode('utf-16le'), key.encode('utf-16le'))
            return units.decode('utf-16le', 'strict')
        normal = _load_object(decrypt_field('encConstants'))
        secret = decode_sdk_secret_constants(decrypt_field('encSecretConstants'), key)
        merged = merge_sdk_string_constants(normal, secret)
        return SdkConfiguration(MappingProxyType(merged), len(normal), len(secret))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError('Invalid GMC2 configuration envelope or constants') from None
