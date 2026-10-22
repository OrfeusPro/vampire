"""Presentation-only regional names from a decoded lobby response, without IO."""
from datetime import datetime
import re

from .game_server_target import SERVER_REGION_CODES, is_game_server_state_excluded
from .lobby_server_list import LobbyServerListResult


def build_account_catalog(listing, *, region, observed_utc):
    if not isinstance(listing, LobbyServerListResult) or listing.result_code != 0 or listing.flags[1]:
        raise ValueError('Expected an accepted ordinary lobby catalog')
    if region not in SERVER_REGION_CODES:
        raise ValueError('Unknown catalog region')
    if datetime.fromisoformat(observed_utc).utcoffset() is None:
        raise ValueError('Catalog observation requires a time zone')
    groups = {}
    for group in listing.groups:
        if group.raw_08 in groups:
            raise ValueError('Ambiguous lobby group')
        groups[group.raw_08] = group
    servers, seen = [], set()
    for record in listing.servers:
        group = groups.get(record.u32[0])
        if group is None or group.raw_20 != SERVER_REGION_CODES[region]:
            continue
        identifier = record.u32[1]
        if not 1 <= identifier <= 0xffffffff or identifier in seen:
            raise ValueError('Ambiguous lobby server')
        seen.add(identifier)
        source_name = record.strings[0].strip()
        group_name = group.text_10.strip()
        suffix = re.search(r'([0-9]+)$', source_name)
        # EU currently supplies Latin group labels and Korean numbered records.
        # Keep the original label if a numeric suffix or group name is unavailable.
        name = group_name + ' ' + suffix[1] if group_name and suffix else source_name
        if not name:
            raise ValueError('Missing lobby server label')
        servers.append(dict(id=identifier, group_id=group.raw_08, name=name,
            source_name=source_name, group_name=group_name, excluded=is_game_server_state_excluded(record)))
    if not servers:
        raise ValueError('No servers in the selected region')
    return dict(region=region, observed_utc=observed_utc, source='fresh_lobby', servers=servers)
