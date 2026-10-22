"""Offline CDN server-list selection, returning raw details without applying IO.

Evidence: HEADLESS-CDN-SERVER-LIST.md. Native type matching/first-entry choice
and field destinations were replayed with JSON/FString shims. Exact JSON names,
types/Unicode/budgets below are local policy. No global endpoint state is shared
between accounts. A selection does not establish endpoint validity/readiness.
"""
from dataclasses import dataclass, field

MAX_SERVERS = 1024
_ASCII_FOLD = str.maketrans('abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')


@dataclass(frozen=True, slots=True)
class CdnServerSelection:
    index: int
    requested_type: str = field(repr=False)
    entry_type: str = field(repr=False)
    lobby_address: str | None = field(repr=False)
    lobby_port: str | None = field(repr=False)
    patch_url: str | None = field(repr=False)
    data_url: str | None = field(repr=False)


def _string(value, limit):
    if not isinstance(value, str) or len(value) > limit or '\0' in value:
        raise ValueError('Invalid CDN server string')
    try:
        encoded = value.encode('utf-16le', 'strict')
    except UnicodeEncodeError:
        raise ValueError('Invalid CDN server string encoding') from None
    if len(encoded) > 2 * limit:
        raise ValueError('CDN server string exceeds local budget')
    return value


def select_cdn_server(document: dict, *, lobby_region=None) -> CdnServerSelection:
    """Select first ASCII-case-insensitive type match using select_server/type.

    Missing item type is skipped; wrong types are local errors. An empty list
    or no match is an error, never a guessed production/default server.
    Missing detail fields return None, meaning no replacement; the client
    preserves its previous values there. No previous account values are copied.

    Host, port and URLs remain strings exactly as supplied. This function does
    not repeat the client's permissive _wtoi port conversion or validate DNS,
    schemes, port ranges, trust, full ReadJson or connection readiness.
    """
    # Current EXE 98802d550890: SetServerList 14565f760 loads d0/e0/f0/100;
    # selector 14563a8f0 maps 5 -> SG, 6 -> NA, 7 -> EU. This explicit local
    # option does not infer a region from the user's network or SDK country.
    region_keys = {'SG': 'lobbyAddressSG', 'NA': 'lobbyAddressNA', 'EU': 'lobbyAddressEU'}
    if lobby_region is not None and (type(lobby_region) is not str or lobby_region not in region_keys):
        raise ValueError('Explicit supported lobby region required')
    if not isinstance(document, dict) or not isinstance(document.get('select_server'), dict):
        raise ValueError('Missing CDN server selection')
    requested = _string(document['select_server'].get('type'), 128)
    servers = document.get('server_list')
    if not isinstance(servers, list) or len(servers) > MAX_SERVERS:
        raise ValueError('Missing or excessive CDN server list')
    folded = requested.translate(_ASCII_FOLD)
    for index, entry in enumerate(servers):
        if not isinstance(entry, dict):
            raise ValueError('Invalid CDN server entry')
        if 'type' not in entry:
            continue
        kind = _string(entry['type'], 128)
        if kind.translate(_ASCII_FOLD) != folded:
            continue
        detail = entry.get('detail', {})
        if not isinstance(detail, dict):
            raise ValueError('Invalid CDN server detail object')
        values = [_string(detail[key], 4096) if key in detail else None
                  for key in ('lobbyAddress', 'lobbyPort', 'patchURL', 'dataURL')]
        if lobby_region is not None:
            key = region_keys[lobby_region]
            regional = _string(detail[key], 4096) if key in detail else None
            # Native count > 1 means a nonempty FString, including its NUL.
            if regional:
                values[0] = regional
        return CdnServerSelection(index, requested, kind, *values)
    raise ValueError('No matching CDN server entry')
