"""Batch source checks for UI names; automatically close only checks actually executed."""
import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ui_layout_schema


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


inventory = module('audit_ui_inventory', 'inventory-ui-names.py')
inspector = module('audit_ui_inspector', 'inspect-ui.py')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(path, expected):
    raw = path.read_bytes()
    if digest(raw) != expected:
        raise ValueError('SHA mismatch: ' + str(path))
    return raw


def audit_variant(root, record, variant, published_schema, classes, dependencies):
    """Verify bytes and decoder provenance; neither infer defaults nor select runtime branches."""
    catalog_path = inventory.child(root / 'ui-catalog', variant['file'])
    package = json.loads(checked(catalog_path, variant['sha256']))
    if (package['asset_sha256'], package['body_sha256']) != (variant['asset_sha256'], variant['body_sha256']):
        raise ValueError('Package hashes differ from published variant')
    stem = Path(package.get('source_file', package['file'])).stem
    asset_path = inventory.child(root / 'ui-layout-study', stem + '.uasset')
    body_path = inventory.child(root / 'ui-layout-study', stem + '.uexp')
    asset = checked(asset_path, variant['asset_sha256'])
    body = checked(body_path, variant['body_sha256'])
    exports = {e['index']: e for e in inspector.exports(asset, body)['exports']}
    projected = [{k: c.get(k) for k in ('name', 'type', 'export', 'sha256', 'parent_chain',
        'local_slots', 'size_constraints', 'container_geometry')} for c in package['controls']]
    if variant['controls'] != projected or variant['root'] != package['root_export']:
        raise ValueError('Published controls/root differ from catalog')
    if variant['slots'] != package['decoded_slots'] or variant['excluded_slots'] != package['excluded_slots']:
        raise ValueError('Published slots differ from catalog')
    for control in variant['controls']:
        source = exports[control['export']]
        if any(control[key] != source[key] for key in ['name', 'type', 'sha256']):
            raise ValueError('Control export differs from package bytes')
    blueprint = variant['root']
    if blueprint is not None and exports[blueprint['index']] != blueprint:
        raise ValueError('Blueprint export differs from package bytes')
    accounted = set()
    for slot in variant['slots'] + variant['excluded_slots']:
        p = slot['provenance']
        index = p['slot_export']
        if index in accounted:
            raise ValueError('Duplicate accounted slot export')
        accounted.add(index)
        source = exports[index]
        if p['sha256'] != source['sha256'] or p['offset'] != source['offset'] or p['file'] != variant['file']:
            raise ValueError('Slot provenance differs from package bytes')
    candidates = {i for i, e in exports.items() if e['type'].endswith('Slot')}
    unaccounted = sorted(candidates - accounted)
    schema = ui_layout_schema.compile_schema(record, variant)
    if schema != published_schema:
        raise ValueError('Local schema reproduction differs')
    expected = []
    for c in variant['controls']:
        if (c['type'] or '').endswith('_C'):
            targets = sorted(classes.get(c['type'], []))
            expected.append(dict(control={k: c[k] for k in ['name', 'type', 'export', 'sha256']},
                candidates=targets, status='class_match_requires_variant_selection' if targets else 'unresolved_class'))
    expected.sort(key=lambda d: (d['control']['export'], d['control']['name']))
    if expected != dependencies:
        raise ValueError('Published class candidates differ from source controls')
    checks = dict(source_hashes=True, controls_and_root_exports=True, slot_provenance=True,
        published_catalog_agreement=True, local_schema_reproduced=True,
        composition_candidates_reproduced=True, slot_candidates_accounted=not unaccounted)
    unknowns = list(schema['unresolved']) + ['active_variant_and_current_client_compatibility']
    if variant['excluded_slots']:
        unknowns.append('excluded_slots_require_decoder_or_inheritance_review')
    if unaccounted:
        unknowns.append('unaccounted_slot_candidates')
    if schema['issues']:
        unknowns.append('local_schema_issues')
    if any(not edge['candidates'] for edge in expected):
        unknowns.append('missing_nested_classes')
    if any(len(edge['candidates']) > 1 for edge in expected):
        unknowns.append('ambiguous_nested_variants')
    return dict(file=variant['file'], source=dict(catalog_sha256=variant['sha256'],
        asset_sha256=variant['asset_sha256'], body_sha256=variant['body_sha256']),
        checks=checks, automatic_source_checks_passed=all(checks.values()),
        implementation_verified=False, runtime_root=None, root_candidates=schema['root_candidates'],
        counts=dict(controls=len(variant['controls']), decoded_slots=len(variant['slots']),
            excluded_slots=len(variant['excluded_slots']), unaccounted_slots=len(unaccounted)),
        unaccounted_slot_exports=unaccounted,
        unaccounted_slot_candidates=[{k: exports[i][k] for k in ('index', 'name', 'type', 'sha256', 'offset', 'size') if k in exports[i]} for i in unaccounted],
        schema_issues=schema['issues'],
        dependencies=expected, unknowns=unknowns)


def build(root, snapshot, families=()):
    root, snapshot = root.resolve(), snapshot.resolve()
    census = inventory.build(root, snapshot)
    manifest_path = snapshot / 'manifest.json'
    manifest = json.loads(manifest_path.read_bytes())

    def published(relative):
        return json.loads(checked(inventory.child(snapshot, relative), manifest['generated_files'][relative]))

    registry = published('registry-index.json')
    schema_index = published('layout-schema-index.json')
    graph = published('composition-graph.json')
    classes = defaultdict(list)
    by_id = {row['id']: row for row in registry}
    for key, node in graph['nodes'].items():
        # Use graph identities for candidates, preserving every historical variant.
        classes[by_id[node['resource_id']]['name'] + '_C'].append(key)
    selected = [r for r in census['records'] if r['flags']['name_contains_UI'] and
        (not families or any(r['path'].startswith('/Game/RED/UI/' + f + '/') for f in families))]
    if not selected:
        raise ValueError('No records selected; check exact family names')
    records, totals = [], Counter()
    for row in selected:
        record = published('windows/' + row['registry_id'] + '.json')
        if (record['id'], record['path'], record['name'], len(record['variants'])) != (
                row['registry_id'], row['path'], row['name'], row['variant_count']):
            raise ValueError('Published record identity differs from inventory')
        result = dict(task_id=row['task_id'], path=row['path'], name=row['name'], variants=[])
        for variant in record['variants']:
            key = record['path'] + '|' + variant['file']
            try:
                if manifest['resources'][key] != variant['sha256']:
                    raise ValueError('Variant differs from manifest')
                entry = schema_index['entries'][key]
                schema = published(entry['file'])
                if digest((snapshot / entry['file']).read_bytes()) != entry['sha256']:
                    raise ValueError('Schema index SHA mismatch')
                value = audit_variant(root, record, variant, schema, classes, graph['nodes'][key]['dependencies'])
                totals.update(value['counts'])
                totals['source_checks_passed' if value['automatic_source_checks_passed'] else 'source_checks_failed'] += 1
            except (ValueError, OSError, KeyError, TypeError, IndexError) as error:
                value = dict(file=variant['file'], automatic_source_checks_passed=False,
                    implementation_verified=False, error=type(error).__name__ + ': ' + str(error))
                totals['source_checks_failed'] += 1
            totals['variants'] += 1
            result['variants'].append(value)
        totals['resources'] += 1
        records.append(result)
    return dict(schema=1, kind='automated_ui_source_audit', selection=dict(uppercase_UI_in_name=True, families=list(families)),
        snapshot=dict(path=str(snapshot), id=manifest['id'], manifest_sha256=digest(manifest_path.read_bytes())),
        tools={p.name: digest(p.read_bytes()) for p in [Path(__file__), HERE/'inspect-ui.py', HERE/'ui_layout_schema.py', HERE/'inventory-ui-names.py', HERE/'build-ui-prototype.py']},
        counts=dict(totals), records=records,
        limits=['Passed checks are automatically confirmed only for the recorded bytes and tool versions.',
            'Raw export hashes and decoded catalog agreement do not prove complete native UProperty decoding.',
            'Candidate dependencies do not select runtime variants; historical/current compatibility remains open.',
            'No visual, event, interaction, game command or 50-window performance completion is claimed.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--family', action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(HERE.parents[3]) or output.is_relative_to(args.snapshot.resolve()):
        parser.error('Keep reports outside the repository and immutable snapshot')
    if output.exists():
        parser.error('Use a new output path; previous evidence is immutable')
    result = build(args.root, args.snapshot, args.family)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
    print(json.dumps(dict(output=str(output), counts=result['counts']), ensure_ascii=False))
    return int(bool(result['counts'].get('source_checks_failed')))


if __name__ == '__main__':
    raise SystemExit(main())
