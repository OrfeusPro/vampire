"""Select one current signed release per bot without downgrading publication."""
import json
import re


def latest_releases(entries):
    versions = {}
    latest = {}
    for signed in entries:
        meta = json.loads(signed['payload'])
        if not re.fullmatch(r'[a-z0-9_-]+', meta['id']):
            raise RuntimeError('Invalid bot id')
        if not re.fullmatch(r'\d+\.\d+\.\d+', meta['version']):
            raise RuntimeError('Invalid bot version')
        if not re.fullmatch(r'[0-9a-f]{64}', meta['sha256']):
            raise RuntimeError('Invalid bot package hash')
        key = (meta['id'], tuple(map(int, meta['version'].split('.'))))
        if key in versions and versions[key] != signed:
            raise RuntimeError('Published bot versions are immutable')
        versions[key] = signed
        if meta['id'] not in latest or key[1] > latest[meta['id']][0]:
            latest[meta['id']] = (key[1], signed)
    return [latest[name][1] for name in sorted(latest)]
