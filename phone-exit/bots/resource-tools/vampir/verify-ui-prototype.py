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
    if (snapshot / 'collection-index.json').exists():
        catalog = json.loads((snapshot / 'collection-index.json').read_text('utf-8'))
        source = catalog['source']
        assert source['sha256'] == manifest['inputs'][source['file']]
        assert source['manifest_sha256'] == manifest['inputs']['maps/collections/manifest.json']
        assert len(catalog['entries']) == catalog['statistics']['collections']
        assert len({row['id'] for row in catalog['entries']}) == len(catalog['entries'])
        assert len(catalog['items']) == catalog['statistics']['items']
        chunks = {}
        for file, digest in catalog['chunks'].items():
            assert digest == manifest['generated_files'][file]
            chunks[file] = json.loads((snapshot / file).read_text('utf-8'))
        requirements = 0
        for row in catalog['entries']:
            entry = chunks[row['file']][row['id']]
            assert entry['id'] == row['id'] and entry['name'] == row['name']
            assert row['requirements'] == len(entry['requirements'])
            requirements += row['requirements']
            for requirement in entry['requirements']:
                assert requirement['row']['GroupId'] == entry['id']
                assert requirement['item_id'] in catalog['items']
        assert requirements == catalog['statistics']['requirements']
        for item_id, file in catalog['items'].items():
            item = chunks[file][item_id]
            assert item['id'] == item_id
            for image in item.get('icon', {}).get('images', []):
                assert image['url'] == 'collection-assets/' + image['sha256'] + '.png'
                assert sha(snapshot / image['url']) == image['sha256']
    if (snapshot / 'skin-evidence.json').exists():
        skins = json.loads((snapshot / 'skin-evidence.json').read_text('utf-8'))
        tokens = json.loads((snapshot / 'skin-tokens.json').read_text('utf-8'))
        assert skins['decoder']['sha256'] == manifest['tools']['inspect-ui.py']
        assert tokens.keys() == skins['roles'].keys()
        for key, role in skins['roles'].items():
            record = next(r for r in index if r['name'] == role['resource'])
            file, source = role['catalog_file'], role['source']
            assert source['catalog_sha256'] == manifest['resources'][record['path'] + '|' + file]
            assert source['package_sha256'] == manifest['inputs']['ui-layout-study/' + file]
            for suffix, field in [('.uasset', 'asset_sha256'), ('.uexp', 'body_sha256')]:
                assert source[field] == manifest['inputs']['ui-layout-study/' + file.removesuffix('.json') + suffix]
            assert tokens[key]['sha256'] == role['texture']['sha256'] == textures[role['asset_path']]['sha256']
            assert tokens[key]['url'] == textures[role['asset_path']]['url']
    if (snapshot / 'placement-evidence.json').exists():
        placements = json.loads((snapshot / 'placement-evidence.json').read_text('utf-8'))
        for profile in placements['profiles'].values():
            record = next(r for r in index if r['name'] == profile['resource'])
            assert manifest['resources'][record['path'] + '|' + profile['catalog_file']] == profile['source']['catalog_sha256']
    if (snapshot / 'button-evidence.json').exists():
        bindings = json.loads((snapshot / 'button-evidence.json').read_text('utf-8'))
        for binding in bindings['bindings'].values():
            record = next(r for r in index if r['name'] == binding['resource'])
            assert manifest['resources'][record['path'] + '|' + binding['catalog_file']] == binding['source']['catalog_sha256']
            assert binding['chain'][-1]['decoded']['parent_export'] == binding['root_export']
    assert sum(row['variants'] for row in index) == manifest['variant_count']
    return dict(state='passed', snapshot=manifest['id'], resources=len(index), textures=len(textures),
                limits='Byte/provenance checks; does not prove visual fidelity, game behavior or 50 browser windows.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.snapshot), ensure_ascii=False))
