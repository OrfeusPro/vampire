"""Bounded native-compatible ASCII URI subset, without network/normalization.

Evidence: HEADLESS-CDN-URI.md. Unsupported or ambiguous forms are rejected as
local policy; native malformed-input behavior is not offered as URL validation.
"""
from dataclasses import dataclass, field
import re


@dataclass(frozen=True, slots=True)
class CdnUri:
    scheme: str
    host: str = field(repr=False)
    port: int
    path: str = field(repr=False)

    @property
    def request_target(self) -> str:
        return '/' + self.path


def parse_cdn_uri_ascii(url: str) -> CdnUri:
    """Parse only explicit lower-case http(s), DNS/IPv4-style host, safe port.

    Local policy: printable ASCII without spaces, <=4096 bytes, no userinfo,
    IPv6, backslash, query or fragment. Host spelling and escapes are preserved;
    remove exactly one path separator. Explicit ports:1..65535,1..5 digits.
    No percent decoding, IDNA, DNS, endpoint trust or connection occurs.
    """
    if (not isinstance(url, str) or len(url) > 4096 or
            any(not 33 <= ord(c) <= 126 for c in url) or any(c in url for c in '\\?#@')):
        raise ValueError('Unsupported CDN URI')
    scheme, separator, tail = url.partition('://')
    if not separator or scheme not in ('http', 'https'):
        raise ValueError('Unsupported CDN URI')
    authority, _, path = tail.partition('/')
    host, colon, port_text = authority.partition(':')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', host):
        raise ValueError('Unsupported CDN authority')
    if colon:
        if not re.fullmatch(r'[0-9]{1,5}', port_text) or not 1 <= int(port_text) <= 65535:
            raise ValueError('Unsupported CDN port')
        port = int(port_text)
    else:
        port = 443 if scheme == 'https' else 80
    return CdnUri(scheme, host, port, path)
