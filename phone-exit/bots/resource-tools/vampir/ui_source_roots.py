"""Attach verified serialized WidgetTree roots to IR without choosing runtime roots."""
import copy
import json
from pathlib import Path
import ui_pipeline as cache


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
