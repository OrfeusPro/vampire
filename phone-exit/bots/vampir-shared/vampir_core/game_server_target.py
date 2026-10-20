"""Explicit game endpoint from a decoded lobby record and verified consumers."""
from dataclasses import dataclass, field
import ipaddress
import re

from .lobby_server_list import LobbyServerListResult


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
    host, port = record.strings[1], record.u16[0]
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
    return GameServerTarget(server_id, record.u32[0], host, port, record.u16[1])
