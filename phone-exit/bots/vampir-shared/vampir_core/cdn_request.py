"""Offline CDN request draft with verified client defaults, without HTTP IO.

Headers, body handling, TLS, redirects and response acceptance are unresolved.
Evidence: HEADLESS-CDN-HTTP.md. Never send this draft as raw HTTP automatically.
"""
from dataclasses import dataclass, field
from .sdk_config import prepare_cdn_config_url_ascii, select_cdn_config_base
from .cdn_uri import CdnUri, parse_cdn_uri_ascii


@dataclass(frozen=True, slots=True)
class CdnConfigRequestDraft:
    """Candidate URL/default method/protocol; not a complete serialized request."""
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
