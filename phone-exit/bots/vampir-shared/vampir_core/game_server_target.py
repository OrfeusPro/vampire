"""Explicit game endpoint from a decoded lobby record and verified consumers."""
from dataclasses import dataclass, field
import ipaddress
import re

from .lobby_server_list import LobbyServerListResult

SERVER_REGION_CODES = {'KR': 1, 'ASIA': 2, 'TW': 3, 'JP': 4, 'SG': 5, 'NA': 6, 'EU': 7}


def is_game_server_state_excluded(record):
    """Native saved-server gate rejects +35 values 2/3; other flags unresolved.

    False does not certify an open server or permission to create characters.
    See HEADLESS-SERVER-ENTRY-STATE.md and the native reset replay.
    """
    return record.enums[1] in (2, 3)


def game_server_allows_joined_country(record, *, joined_country_code):
    """Native array50 country predicate, using an explicit fresh SDK country.

    Empty arrays impose no country restriction. For nonempty arrays, local
    policy requires a two-letter ASCII country, with no network-country fallback.
    Native permits empty-string matches; that unsupported context is rejected.
    """
    if not record.array50: return True
    if type(joined_country_code) is not str or re.fullmatch(r'[A-Za-z]{2}', joined_country_code) is None:
        raise ValueError('Explicit SDK joined country required for server country policy')
    code = joined_country_code.upper()
    return any(value.isascii() and value.upper() == code for value in record.array50)


@dataclass(frozen=True, slots=True)
class GameServerTarget:
    server_id: int
    group_id: int
    host: str = field(repr=False)
    port: int
    other_word: int = field(repr=False)


def select_game_server_target(server_list, *, server_id):
    """Record +0c is lookup ID, +08 group, +20 host, +30 game port.

    No automatic choice, override host, interpretation of availability flags,
    auth token or socket IO. Local policy restricts ports to 1..32767 and
    hosts to public literal IPv4 or bounded ASCII DNS names. DNS destinations
    must still be resolved and checked by the selected transport/exit owner.
    """
    if not isinstance(server_list, LobbyServerListResult): raise TypeError('Expected decoded lobby server list')
    if server_list.result_code != 0: raise ValueError('Lobby server list failed')
    if server_list.flags[1]: raise ValueError('Lobby handler uses an alternate list branch')
    if type(server_id) is not int or not 1 <= server_id <= 0xffffffff:
        raise ValueError('Explicit nonzero uint32 server ID required')
    records = [record for record in server_list.servers if record.u32[1] == server_id]
    if len(records) != 1: raise ValueError('Selected server is absent or ambiguous')
    record = records[0]
    host, port = validate_public_game_endpoint(record.strings[1], record.u16[0])
    return GameServerTarget(server_id, record.u32[0], host, port, record.u16[1])


def validate_public_game_endpoint(host, port):
    """Validate endpoint syntax; the transport must also check resolved IPs."""
    if type(host) is not str or not 1 <= len(host) <= 253 or type(port) is not int or not 1 <= port <= 32767:
        raise ValueError('Game endpoint is outside supported local bounds')
    try: address = ipaddress.ip_address(host)
    except ValueError:
        # Numeric-looking malformed IPv4 is never reinterpreted as a hostname.
        if all(c in '0123456789.' for c in host): raise ValueError('Invalid game IPv4 address') from None
        labels = host.split('.')
        if len(labels) < 2 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', p) for p in labels):
            raise ValueError('Invalid game DNS hostname') from None
        if labels[-1].isdigit() or host.lower().endswith(('.localhost', '.local', '.internal')):
            raise ValueError('Unsupported game DNS destination')
    else:
        if address.version != 4 or not address.is_global: raise ValueError('Expected public game IPv4 destination')
    return host, port


def select_game_server_in_region(server_list, *, region, server_id=None, joined_country_code=None):
    """Explicit region gate by group +20, matching native master Update.

    With no ID, choose the lowest valid unique ID inside that region as a
    local diagnostic policy. Exclude native saved-server states 2/3; no fallback
    region or claim that remaining records permit entry/character creation.
    Nonempty array50 requires the current SDK joined country, not exit country.
    See HEADLESS-SERVER-REGION-SELECTION.md for enum and gate native evidence.
    """
    if type(region) is not str or region not in SERVER_REGION_CODES:
        raise ValueError('Explicit supported server region required')
    if not isinstance(server_list, LobbyServerListResult): raise TypeError('Expected decoded lobby server list')
    if server_id is not None and (type(server_id) is not int or not 1 <= server_id <= 0xffffffff):
        raise ValueError('Invalid explicit server ID')
    identifiers = [server_id] if server_id is not None else sorted({r.u32[1] for r in server_list.servers})
    for identifier in identifiers:
        try: target = select_game_server_target(server_list, server_id=identifier)
        except ValueError:
            if server_id is not None: raise
            continue
        groups = [g for g in server_list.groups if g.raw_08 == target.group_id]
        if len(groups) == 1 and groups[0].raw_20 == SERVER_REGION_CODES[region]:
            record = next(r for r in server_list.servers if r.u32[1] == identifier)
            if is_game_server_state_excluded(record):
                if server_id is not None:
                    raise ValueError('Selected server state is excluded by native saved-server policy')
                continue
            try: country_allowed = game_server_allows_joined_country(record, joined_country_code=joined_country_code)
            except ValueError:
                if server_id is not None: raise
                continue
            if not country_allowed:
                if server_id is not None:
                    raise ValueError('Selected server does not allow the SDK joined country')
                continue
            return target
    raise ValueError('No unique valid endpoint in the explicitly selected region')
