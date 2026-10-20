"""Bounded numeric ClientVersion from an explicitly supplied patch manifestlist.

No filesystem, download, installation, default revision or freshness claim.
"""
import json
import re


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('Duplicate patch manifest key')
        result[key] = value
    return result


def parse_patch_client_revision(body):
    """Local strict policy: canonical Revision<uint32>, no CRT prefix quirks.

    Caller establishes file/source version and account-independent provenance.
    Does not validate all manifest entries or establish completed patch state.
    """
    if type(body) is not bytes or not 1 <= len(body) <= 2097152:
        raise ValueError('Patch manifest exceeds local byte budget')
    try:
        document = json.loads(body.decode('utf-8-sig'), object_pairs_hook=_unique)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('Invalid patch manifest JSON') from None
    if type(document) is not dict or type(document.get('ClientVersion')) is not str:
        raise ValueError('Missing patch ClientVersion')
    match = re.fullmatch(r'Revision([1-9][0-9]{0,9})', document['ClientVersion'])
    if match is None or int(match[1]) > 0xffffffff:
        raise ValueError('Unsupported patch ClientVersion')
    return int(match[1])
