"""Verify published prototype bytes and source provenance without opening a game."""
import argparse
import hashlib
import json
from pathlib import Path
import ui_desired_geometry
import ui_composition_graph
import ui_layout_schema


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(snapshot):
    manifest = json.loads((snapshot / 'manifest.json').read_text('utf-8'))
    if (snapshot / 'display-settings.json').exists():
        display = json.loads((snapshot / 'display-settings.json').read_text('utf-8'))
        assert hashlib.sha256(json.dumps(display, sort_keys=True).encode()).hexdigest() == manifest['display_settings']['sanitized_sha256']
        assert set(display['saved']) <= {'ResolutionSizeX', 'ResolutionSizeY', 'LastUserConfirmedResolutionSizeX', 'LastUserConfirmedResolutionSizeY', 'DesiredScreenWidth', 'DesiredScreenHeight', 'LastUserConfirmedDesiredScreenWidth', 'LastUserConfirmedDesiredScreenHeight', 'FullscreenMode', 'LastConfirmedFullscreenMode'}
        assert display['ui_scale']['value'] is None and display['ui_scale']['status'] == 'unresolved_active_setting'
    for name, digest in manifest.get('generated_files', {}).items():
        assert sha(snapshot / name) == digest, 'Changed generated file: ' + name
    textures = json.loads((snapshot / 'textures.json').read_text('utf-8'))
    if (snapshot / 'status-skin.json').exists():
        status_skin = json.loads((snapshot / 'status-skin.json').read_text('utf-8'))
        assert status_skin['schema'] == 1 and status_skin['texture'] in textures, 'Missing published HP/MP frame texture'
        assert set(status_skin['brushes']) == {'Image', 'Image_224'}
        assert all(b['resource_reference']['path'] == status_skin['texture'] + '.ProgressBG_HP'
                   for b in status_skin['brushes'].values()), 'Frame Brush points at a different texture'
        assert set(status_skin['portrait_brushes']) == {'ImageBG', 'ImageFrame', 'ImagePortrait'}
        assert all(b['asset_path'] in textures for b in status_skin['portrait_brushes'].values()), 'Missing published portrait resource'
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
            if binding.get('desired_trees'):
                assert manifest['tools']['ui_desired_geometry.py'] == sha(Path(__file__).with_name('ui_desired_geometry.py'))
                window = json.loads((snapshot / 'windows' / (record['id'] + '.json')).read_text('utf-8'))
                variant = next(v for v in window['variants'] if v['file'] == binding['catalog_file'])
                policy = binding['measure_desired']
                rebuilt = ui_desired_geometry.compile_tree(dict(controls=variant['controls'], decoded_slots=variant['slots']), policy['control'], policy)
                assert rebuilt == binding['desired_trees'], 'Desired-size tree differs from source controls'
    if (snapshot / 'component-evidence.json').exists():
        components = json.loads((snapshot / 'components.json').read_text('utf-8'))
        evidence = json.loads((snapshot / 'component-evidence.json').read_text('utf-8'))
        assert evidence['modules'].keys() == components['modules'].keys()
        assert evidence['references'] == components.get('references', [])
        def check_component_control(source, control):
            record = next(r for r in index if r['path'] == source['resource_path'])
            file = source['catalog_file']
            assert source['catalog_sha256'] == manifest['resources'][record['path'] + '|' + file]
            window = json.loads((snapshot / 'windows' / (record['id'] + '.json')).read_text('utf-8'))
            variant = next(v for v in window['variants'] if v['file'] == file)
            original = next(c for c in variant['controls'] if c['export'] == control['export'])
            assert all(original[k] == v for k, v in control.items()), 'Changed component control'
        for key, module in evidence['modules'].items():
            spec = components['modules'][key]
            assert [c['name'] for c in module['controls']] == spec['members']
            for control in module['controls']:
                check_component_control(module['source'], control)
            if module.get('frame_root'):
                check_component_control(module['source'], module['frame_root'])
                assert module['frame_root']['name'] == spec['frame_root']
            for projection in module.get('projection', []):
                check_component_control(module['source'], projection['control_source'])
                assert projection['binding'] == spec['render_bindings'][projection['key']]
                assert projection['control_source']['type'] == projection['binding']['kind']
            assert len(module.get('projection', [])) == len(spec.get('render_bindings', {}))
            for dependency in module['dependencies']:
                check_component_control(module['source'], dependency['control_source'])
                assert dependency['control_source']['type'] == components['modules'][dependency['module']]['resource'] + '_C'
            for binding_id in spec.get('bindings', {}).values():
                assert bindings['bindings'][binding_id]['catalog_file'] == module['source']['catalog_file']
        assert len(evidence['consumers']) == len(components['consumers'])
        for consumer, spec in zip(evidence['consumers'], components['consumers']):
            assert all(consumer[k] == v for k, v in spec.items())
            check_component_control(consumer['source'], consumer['control_source'])
            assert consumer['control_source']['type'] == components['modules'][consumer['module']]['resource'] + '_C'
    if (snapshot / 'composition-graph.json').exists():
        graph = json.loads((snapshot / 'composition-graph.json').read_text('utf-8'))
        assert graph == ui_composition_graph.from_snapshot(snapshot), 'Composition graph differs from source records'
        assert manifest['tools']['ui_composition_graph.py'] == sha(Path(__file__).with_name('ui_composition_graph.py'))
    if (snapshot / 'layout-schema-index.json').exists():
        import ui_source_roots
        root_report = None
        if (snapshot / 'source-widget-roots.json').exists():
            root_report = ui_source_roots.read(snapshot / 'source-widget-roots.json', manifest['generated_files']['source-widget-roots.json'])
            assert manifest['tools']['ui_source_roots.py'] == sha(Path(__file__).with_name('ui_source_roots.py'))
        schemas = json.loads((snapshot / 'layout-schema-index.json').read_text('utf-8'))
        assert manifest['tools']['ui_layout_schema.py'] == sha(Path(__file__).with_name('ui_layout_schema.py'))
        expected_keys = set()
        totals = dict(variants=0, nodes=0, slots=0, issues=0, excluded_slots=0)
        for row in index:
            record = json.loads((snapshot / 'windows' / (row['id'] + '.json')).read_text('utf-8'))
            for variant in record['variants']:
                key = record['path'] + '|' + variant['file']
                expected_keys.add(key)
                spec = schemas['entries'][key]
                assert spec['source_sha256'] == variant['sha256']
                assert sha(snapshot / spec['file']) == spec['sha256']
                compiled = json.loads((snapshot / spec['file']).read_text('utf-8'))
                expected = ui_layout_schema.compile_schema(record, variant)
                if root_report is not None:
                    expected = ui_source_roots.compile_schema(record, variant, root_report)
                assert compiled == expected, 'Widget schema differs from source slots / root annotations'
                totals['variants'] += 1
                for field in ('nodes', 'slots', 'issues', 'excluded_slots'):
                    assert spec[field] == len(compiled[field])
                    totals[field] += spec[field]
        assert expected_keys == schemas['entries'].keys()
        assert schemas['statistics'] == totals
        component_layouts = json.loads((snapshot / 'component-layouts.json').read_text('utf-8'))
        for key, spec in components['modules'].items():
            source = evidence['modules'][key]['source']
            assert component_layouts[key] == schemas['entries'][source['resource_path'] + '|' + source['catalog_file']]
    assert sum(row['variants'] for row in index) == manifest['variant_count']
    return dict(state='passed', snapshot=manifest['id'], resources=len(index), textures=len(textures),
                limits='Byte/provenance checks; does not prove visual fidelity, game behavior or 50 browser windows.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.snapshot), ensure_ascii=False))
