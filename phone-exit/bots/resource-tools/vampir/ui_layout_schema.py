"""Compile source-bound local widget/slot IR without selecting a visible runtime root."""
import copy
import hashlib
import json
from collections import Counter, deque


def compile_schema(record, variant):
    source = dict(resource_id=record['id'], resource_path=record['path'],
        catalog_file=variant['file'], catalog_sha256=variant['sha256'],
        asset_sha256=variant.get('asset_sha256'), body_sha256=variant.get('body_sha256'),
        archive=copy.deepcopy(variant.get('source')), entry=variant.get('entry'))
    nodes, slots, issues = {}, {}, []
    for control in sorted(variant['controls'], key=lambda c: c['export']):
        key = str(control['export'])
        if key in nodes:
            raise ValueError('Повторный export контрола: ' + key)
        kind = control['type'] or 'unknown'
        metadata = kind.startswith('MovieScene') or kind in ('WidgetAnimation', 'WidgetTree')
        nodes[key] = dict(name=control['name'], kind=kind,
            category='metadata' if metadata else 'widget_candidate',
            source=dict(export=control['export'], sha256=control['sha256']),
            properties={k: copy.deepcopy(control[k]) for k in ('size_constraints', 'container_geometry') if control.get(k) is not None},
            incoming=[], children=[])
    for slot in sorted(variant.get('slots', []), key=lambda s: s['provenance']['slot_export']):
        key = str(slot['provenance']['slot_export'])
        if key in slots:
            raise ValueError('Повторный export слота: ' + key)
        slots[key] = copy.deepcopy(slot)
        decoded = slot['decoded']
        parent, child = str(decoded['parent_export']), str(decoded['content_export'])
        if parent not in nodes or child not in nodes:
            issues.append(dict(code='dangling_slot', slot=key, parent=parent, child=child))
        if parent in nodes:
            nodes[parent]['children'].append(dict(slot=key, child=child))
        if child in nodes:
            nodes[child]['incoming'].append(dict(slot=key, parent=parent))
    for key, node in nodes.items():
        if len(node['incoming']) > 1:
            issues.append(dict(code='multiple_parents', node=key))
    # A nonrecursive topological pass also detects cycles disconnected from roots.
    degrees = {k: 0 for k in nodes}
    for node in nodes.values():
        for edge in node['children']:
            if edge['child'] in degrees:
                degrees[edge['child']] += 1
    queue = deque(k for k, degree in degrees.items() if not degree)
    while queue:
        for edge in nodes[queue.popleft()]['children']:
            if edge['child'] in degrees:
                degrees[edge['child']] -= 1
                if not degrees[edge['child']]:
                    queue.append(edge['child'])
    remaining = sorted(k for k, degree in degrees.items() if degree)
    if remaining:
        issues.append(dict(code='cycle_or_dependent_on_cycle', nodes=remaining))
    return dict(schema=1, kind='local_widget_schema', source=source,
        blueprint_root=copy.deepcopy(variant.get('root')), runtime_root=None,
        root_candidates=[k for k, n in nodes.items() if not n['incoming'] and n['category'] == 'widget_candidate'],
        nodes=nodes, slots=slots, excluded_slots=copy.deepcopy(variant.get('excluded_slots', [])),
        issues=issues, unresolved=['runtime_root_and_visibility', 'external_allocation_and_dpi', 'safezone_scale_rendertransform_zorder',
            'inherited_defaults_and_desired_size', 'brush_style_font_material', 'event_bindings_and_data'],
        source_limits=copy.deepcopy(variant.get('limitations', [])))


def publish(records, folder, source_roots=None):
    directory = folder / 'layout-schemas'
    directory.mkdir(exist_ok=True)
    entries, totals = {}, Counter()
    for record in records:
        for variant in record['variants']:
            schema = compile_schema(record, variant)
            if source_roots is not None:
                import ui_source_roots
                schema = ui_source_roots.compile_schema(record, variant, source_roots)
            data = json.dumps(schema, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            digest = hashlib.sha256(data).hexdigest()
            file = 'layout-schemas/' + digest + '.json'
            (folder / file).write_bytes(data)
            entries[record['path'] + '|' + variant['file']] = dict(file=file, sha256=digest,
                source_sha256=variant['sha256'], nodes=len(schema['nodes']), slots=len(schema['slots']),
                issues=len(schema['issues']), excluded_slots=len(schema['excluded_slots']))
            totals.update(variants=1, nodes=len(schema['nodes']), slots=len(schema['slots']), issues=len(schema['issues']), excluded_slots=len(schema['excluded_slots']))
    return dict(schema=1, entries=entries, statistics=dict(totals),
        status='structure_compiled_not_runtime_verified')
