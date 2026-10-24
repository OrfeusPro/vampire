"""Verify published prototype bytes and source provenance without opening a game."""
import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(snapshot):
    manifest = json.loads((snapshot / 'manifest.json').read_text('utf-8'))
    for name, digest in manifest.get('generated_files', {}).items():
        assert sha(snapshot / name) == digest, 'Changed generated file: ' + name
    textures = json.loads((snapshot / 'textures.json').read_text('utf-8'))
    index = json.loads((snapshot / 'registry-index.json').read_text('utf-8'))
    assert len(index) == manifest['registry_count'], 'Incomplete registry'
    assert len({row['id'] for row in index}) == len(index), 'Duplicate resource IDs'
    for row in index:
        record = json.loads((snapshot / 'windows' / (row['id'] + '.json')).read_text('utf-8'))
        assert row['path'] == record['path'] and row['variants'] == len(record['variants'])
        for variant in record['variants']:
            assert variant['sha256'] == manifest['resources'][row['path'] + '|' + variant['file']]
    for name, texture in textures.items():
        actual = sha(snapshot / texture['url'])
        assert actual == texture['sha256'] == manifest['images'][name], 'Changed texture: ' + name
    for name, digest in manifest['implementation'].items():
        if '.test.' not in name:
            assert sha(snapshot / name) == digest, 'Changed source: ' + name
    if (snapshot / 'placement-evidence.json').exists():
        placements = json.loads((snapshot / 'placement-evidence.json').read_text('utf-8'))
        for profile in placements['profiles'].values():
            record = next(r for r in index if r['name'] == profile['resource'])
            assert manifest['resources'][record['path'] + '|' + profile['catalog_file']] == profile['source']['catalog_sha256']
    assert sum(row['variants'] for row in index) == manifest['variant_count']
    return dict(state='passed', snapshot=manifest['id'], resources=len(index), textures=len(textures),
                limits='Byte/provenance checks; does not prove visual fidelity, game behavior or 50 browser windows.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.snapshot), ensure_ascii=False))
