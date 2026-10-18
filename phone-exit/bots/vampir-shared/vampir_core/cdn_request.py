"""Offline CDN request draft with verified client defaults, without HTTP IO.

Headers, body handling, TLS, redirects and response acceptance are unresolved.
Evidence: HEADLESS-CDN-HTTP.md. Never send this draft as raw HTTP automatically.
"""
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .sdk_config import prepare_cdn_config_url_ascii, select_cdn_config_base


@dataclass(frozen=True, slots=True)
class CdnConfigRequestDraft:
    """Candidate URL/default method/protocol; not a complete serialized request."""
    url: str = field(repr=False)
    method: str = field(default='GET', init=False)
    http_version: str = field(default='1.0', init=False)


def _checked_https_url(url):
    if (not isinstance(url, str) or len(url) > 4096 or
            any(c.isspace() or not 33 <= ord(c) <= 126 for c in url) or any(c in url for c in '\\?#')):
        raise ValueError('Invalid CDN request URL')
    try:
        parsed = urlsplit(url)
        valid = (parsed.scheme.lower() == 'https' and bool(parsed.hostname) and
                 parsed.username is None and parsed.password is None and not parsed.netloc.endswith(':'))
        parsed.port
    except ValueError:
        raise ValueError('Invalid CDN request URL') from None
    if not valid:
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
    if parsed.netloc.lower() != urlsplit(selected).netloc.lower():
        raise ValueError('CDN assembly changed the configured authority')
    return CdnConfigRequestDraft(url)
