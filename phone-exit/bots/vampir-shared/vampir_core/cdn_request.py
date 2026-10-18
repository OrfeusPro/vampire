"""Offline CDN request draft with verified client defaults, without HTTP IO.

Default empty-body GET headers are verified; body handling, TLS, redirects and
response acceptance remain unresolved. Evidence: HEADLESS-CDN-HEADERS.md.
No automatic transmission or source settings acquisition.
"""
from dataclasses import dataclass, field
from .sdk_config import prepare_cdn_config_url_ascii, select_cdn_config_base
from .cdn_uri import CdnUri, parse_cdn_uri_ascii


@dataclass(frozen=True, slots=True)
class CdnConfigRequestDraft:
    """Explicit URL and verified default GET header; no transport or response IO."""
    url: str = field(repr=False)
    method: str = field(default='GET', init=False)
    http_version: str = field(default='1.0', init=False)
    uri: CdnUri = field(init=False, repr=False)

    def __post_init__(self):
        object.__setattr__(self, 'uri', _checked_https_url(self.url))

    @property
    def request_line(self) -> bytes:
        """Verified first line only; headers/blank line/body are not serialized."""
        return ('GET ' + self.uri.request_target + ' HTTP/1.0\r\n').encode('ascii')

    @property
    def header_bytes(self) -> bytes:
        """Verified default header block for empty-body GET; never sends it."""
        return encode_cdn_get_headers(self.url)


def encode_cdn_get_headers(url: str) -> bytes:
    """Native default GET/1.0 + explicit Host port + Aqua/1.0 + final CRLF.

    Only supported URI subset, empty query/body/cookie/range/additional headers,
    default User-Agent, no keep-alive override. Does not implement POST or
    arbitrary header injection. HTTP and HTTPS parse here; drafts require HTTPS.
    """
    uri = parse_cdn_uri_ascii(url)
    header = ('GET ' + uri.request_target + ' HTTP/1.0\r\n'
              'Host: ' + uri.host + ':' + str(uri.port) + '\r\n'
              'User-Agent: Aqua/1.0\r\n\r\n').encode('ascii')
    if len(header) > 8192:
        raise ValueError('CDN header exceeds local budget')
    return header


def _checked_https_url(url):
    try:
        parsed = parse_cdn_uri_ascii(url)
    except ValueError:
        raise ValueError('Invalid CDN request URL') from None
    if parsed.scheme != 'https':
        raise ValueError('Invalid CDN request URL')
    return parsed


def draft_cdn_config_request(*, normal: str, qa: str, prefix: str, app_version: str,
                             platform_code: int) -> CdnConfigRequestDraft:
    """Bind explicit settings to a strict local HTTPS URL and native defaults.

    Local policy rejects userinfo/query/fragment, whitespace, backslash, invalid
    host/port and non-HTTPS. Check bases before assembly, so platform cannot
    become a missing hostname. No DNS, server trust decision or HTTP occurs.
    """
    _checked_https_url(normal)
    _checked_https_url(qa)
    url = prepare_cdn_config_url_ascii(normal=normal, qa=qa, prefix=prefix,
                                     app_version=app_version, platform_code=platform_code)
    parsed = _checked_https_url(url)
    selected = select_cdn_config_base(normal=normal, qa=qa, prefix=prefix)
    base = _checked_https_url(selected)
    if (parsed.host.lower(), parsed.port) != (base.host.lower(), base.port):
        raise ValueError('CDN assembly changed the configured authority')
    return CdnConfigRequestDraft(url)
