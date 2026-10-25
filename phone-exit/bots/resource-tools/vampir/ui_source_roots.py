"""Attach verified serialized WidgetTree roots to IR without choosing runtime roots."""
import copy
import hashlib
import json
from pathlib import Path
import ui_pipeline as cache


def containers_for(variant, report):
    rows = [r for r in report.get('container_candidates', []) if
            (r['asset_sha256'], r['body_sha256'], r['source_owner_root']) ==
            (variant.get('asset_sha256'), variant.get('body_sha256'), (variant.get('root') or {}).get('index'))]
    exact = [r for r in rows if r['source_file'] == variant['file']]
    return exact or rows


def compile_schema(record, variant, report):
    import ui_layout_schema
    if 'container_candidates' not in report:
        return annotate(ui_layout_schema.compile_schema(record, variant), report)
    enriched = copy.deepcopy(variant)
    added = {}
    for row in containers_for(variant, report):
        entry = row['export']
        if entry['type'] != 'NamedSlot' or row['imported_class'] != '/Script/UMG.NamedSlot':
            raise ValueError('Unreviewed source container kind')
        if row.get('geometry_verified') is not False or row.get('inherited_properties_decoded') is not False:
            raise ValueError('Source container must not promote inherited geometry')
        payload = bytes.fromhex(row['raw_hex'])
        if len(payload) != entry['size'] or hashlib.sha256(payload).hexdigest() != entry['sha256']:
            raise ValueError('Source container payload differs')
        key = entry['index']
        if key in added:
            if added[key]['sha256'] != entry['sha256']:
                raise ValueError('Conflicting source container exports')
            continue
        added[key] = entry
        existing = next((c for c in enriched['controls'] if c['export'] == key), None)
        if existing:
            if existing['sha256'] != entry['sha256'] or existing['type'] != entry['type']:
                raise ValueError('Source container differs from existing control')
            continue
        enriched['controls'].append(dict(export=key, name=entry['name'], type=entry['type'],
            sha256=entry['sha256'], size_constraints=None, container_geometry=None))
    schema = ui_layout_schema.compile_schema(record, enriched)
    schema['source_container_candidates'] = copy.deepcopy(containers_for(variant, report))
    if added:
        schema['unresolved'].append('named_slot_inherited_properties_and_geometry')
    return annotate(schema, report)


def read(path, expected_sha):
    path = Path(path)
    if cache.sha(path) != expected_sha:
        raise ValueError('Source root report SHA differs')
    value = json.loads(path.read_bytes())
    if value.get('schema') != 1 or value.get('kind') != 'source_widget_tree_roots':
        raise ValueError('Unsupported source root report')
    seen = set()
    for row in value['records']:
        key = (row['source_file'], row['export']['index'])
        if key in seen:
            raise ValueError('Duplicate WidgetTree source root')
        seen.add(key)
        if row.get('runtime_root') is not None or row.get('geometry_verified') is not False:
            raise ValueError('Source annotation must not promote runtime geometry')
    return value


def annotate(schema, report):
    source = schema['source']
    rows = [r for r in report['records'] if r['source_file'] == source['catalog_file']]
    basis = 'catalog_file'
    if not rows:
        # Split variants may have distinct catalog names for identical physical packages.
        # Keep every matching provenance record; do not pick an archive or active variant.
        rows = [r for r in report['records'] if
                (r['asset_sha256'], r['body_sha256']) == (source['asset_sha256'], source['body_sha256'])]
        basis = 'full_package_sha_pair'
    annotations, gaps = [], []
    for row in rows:
        if (row['asset_sha256'], row['body_sha256']) != (source['asset_sha256'], source['body_sha256']):
            raise ValueError('Source root package differs from IR')
        if row.get('source_owner_root') != (schema.get('blueprint_root') or {}).get('index'):
            continue
        if row['status'] == 'explicit_local_root_candidate':
            for entry in [row['export'], row['source_root_widget']]:
                node = schema['nodes'].get(str(entry['index']))
                if node is None:
                    gaps.append(dict(widget_tree=row['export']['index'], export=entry['index'],
                        kind=entry['type'], source_sha256=entry['sha256'], reason='source_export_not_projected_in_local_ir'))
                elif node['source']['sha256'] != entry['sha256'] or node['kind'] != entry['type']:
                    raise ValueError('Source root export differs from IR')
        annotations.append(copy.deepcopy(row))
    schema['source_widget_trees'] = annotations
    schema['source_widget_tree_match_basis'] = basis if annotations else None
    schema['source_widget_tree_ir_gaps'] = gaps
    schema['source_widget_tree_status'] = 'annotated' if annotations else 'not_resolved_no_fallback'
    # Keep solver roots and runtime state independent from serialized evidence.
    return schema
