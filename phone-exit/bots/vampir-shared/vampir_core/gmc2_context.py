"""Current-source geo fields and one short-lived in-memory SDK input bundle.

Strict local object/string/IPv4 policy, not a whole native JSON parser.
No snapshots, device values or public IPs are persisted by this module.
"""
from dataclasses import dataclass, field
import hashlib
import ipaddress
import time

from .cdn_config import _load_object
from .gmc2_decode import MAX_XOR_BYTES
from .nid_metadata import _metadata_text

SOURCE_SHA256 = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
CURRENT_SOURCE_SHA256 = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
VERIFIED_SOURCE_SHA256 = frozenset((SOURCE_SHA256, CURRENT_SOURCE_SHA256))
MAX_CONTEXT_AGE = 300  # Local policy; not a recovered SDK timeout.


@dataclass(frozen=True, slots=True)
class Gmc2Geo:
    client_ip: str = field(repr=False)
    country: str = field(repr=False)
    iso_country: str = field(repr=False)
    body_sha256: str
    source_sha256: str = SOURCE_SHA256

    def metadata(self, *, previous_country):
        # The caller owns this state; never borrow the official game's cache.
        _metadata_text(previous_country)
        if type(self.source_sha256) is not str or self.source_sha256 not in VERIFIED_SOURCE_SHA256:
            raise ValueError('GMC2 geo policy is not verified for this source')
        sentinel = self.country in ('A1', 'a1') if self.source_sha256 == CURRENT_SOURCE_SHA256 else self.country == 'A1'
        country = previous_country if sentinel and previous_country else self.country
        return dict(I_ConnectIP=self.client_ip, I_CountryCD=country)


def decode_gmc2_geo(body, *, source_sha256):
    """Use clientIp and geoLocation, never substitute isoCountry for the latter.

    The success/constant envelope is also validated by the SDK decoder. Extra
    fields are ignored; missing, empty, non-string or escaped metadata values
    are rejected locally rather than coerced like native numeric/bool branches.
    """
    if type(source_sha256) is not str or source_sha256 not in VERIFIED_SOURCE_SHA256:
        raise ValueError('GMC2 geo policy is not verified for this source')
    try:
        if type(body) is not bytes or len(body) > MAX_XOR_BYTES:
            raise ValueError
        document = _load_object(body.decode('utf-8-sig', 'strict'), allow_nul_strings=True)
        if type(document.get('errorCode')) is not int or document['errorCode'] != 0:
            raise ValueError
        geo = document['resultData']['geoIp']
        if type(geo) is not dict:
            raise ValueError
        values = [geo[key] for key in ('clientIp', 'geoLocation', 'isoCountry')]
        for value in values:
            if not _metadata_text(value):
                raise ValueError
        ip, country, iso = values
        address = ipaddress.IPv4Address(ip)
        if not address.is_global or address.is_multicast or str(address) != ip:
            raise ValueError
        # CountryCode is source-bound text; A1 is valid, unlike ISO country.
        if len(iso) != 2 or any(not 'A' <= c <= 'Z' for c in iso):
            raise ValueError
        return Gmc2Geo(ip, country, iso, hashlib.sha256(body).hexdigest(), source_sha256)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ValueError('Invalid GMC2 geo context') from None


@dataclass(frozen=True, slots=True)
class SdkInputs:
    email: str = field(repr=False)
    binding: object = field(repr=False)
    profile: dict = field(repr=False)
    constants: dict = field(repr=False)
    selected_profile: str
    route_port: int | None
    source_sha256: str
    geo: Gmc2Geo = field(repr=False)
    fetched_at: float = field(repr=False)

    def __iter__(self):
        # Keep the existing binding/profile/constants unpacking interface.
        return iter((self.binding, self.profile, self.constants))

    def check_usage(self, *, email, selected_profile, route, now=None):
        age = (time.monotonic() if now is None else now) - self.fetched_at
        if (email != self.email or selected_profile != self.selected_profile
                or type(self.source_sha256) is not str or self.source_sha256 not in VERIFIED_SOURCE_SHA256
                or not isinstance(self.geo, Gmc2Geo) or self.geo.source_sha256 != self.source_sha256
                or (route.port if route else None) != self.route_port):
            raise ValueError('SDK context source, account or route differs')
        if not 0 <= age <= MAX_CONTEXT_AGE:
            raise ValueError('SDK context expired; fetch fresh configuration')
