"""Index extracted WidgetBlueprints with controls, slot geometry and provenance.

Variants remain separate. A resource link is not an absolute screen coordinate.
"""
import hashlib
import json
import os
from collections import defaultdict
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))


def parent_chain(content, slots):
    chain, seen = [], {content}
    while slots.get(content):
        choices = slots[content]
        if len(choices) != 1:
            return chain, 'ambiguous_parent'
        slot = choices[0]
        parent = slot['decoded']['parent_export']
        if parent in seen:
            return chain, 'cycle'
        chain.append(dict(slot_export=slot['provenance']['slot_export'], parent_export=parent))
        seen.add(parent)
        content = parent
    return chain, 'no_further_decoded_slot'


def size_constraints(decoded):
    explicit = decoded['explicit_properties']
    constraints = {}
    for name in ('WidthOverride', 'HeightOverride', 'MinDesiredWidth', 'MinDesiredHeight',
                 'MaxDesiredWidth', 'MaxDesiredHeight', 'MinAspectRatio', 'MaxAspectRatio'):
        flag = explicit.get('bOverride_' + name)
        if flag is True and name in explicit:
            constraints[name] = dict(status='explicitly_enabled', value=explicit[name])
        elif flag is False:
            constraints[name] = dict(status='explicitly_disabled', stored_value=explicit.get(name))
        else:
            constraints[name] = dict(status='unresolved_default_or_archetype', stored_value=explicit.get(name), enabled_flag=flag)
    return constraints


def main():
    folder = ROOT / 'ui-layout-study'
    geometry = ROOT / 'ui-geometry'
    by_file, failed_by_file = defaultdict(list), defaultdict(list)
    containers, container_failures = {}, {}
    container_schemas = {}
    for container_file in ('size-boxes.json', 'scale-boxes.json'):
        container_report = geometry / container_file
        if not container_report.exists():
            continue
        sizes = json.loads(container_report.read_text(encoding='utf-8'))
        container_schemas[sizes['container_kind']] = sizes['native_schema']
        for row in sizes['boxes']:
            containers[(row['provenance']['file'], row['provenance']['export'])] = row
        for row in sizes['failures']:
            container_failures[(row['provenance']['file'], row['provenance']['export'])] = row
    for file in ('canvas-slots.json', 'panel-slots.json'):
        parsed = json.loads((geometry / file).read_text(encoding='utf-8'))
        for row in parsed['slots']:
            by_file[row['provenance']['file']].append(row)
        for row in parsed['failures']:
            failed_by_file[row['provenance']['file']].append(row)
    windows, ignored, resources = [], [], defaultdict(list)
    for package in json.loads((folder / 'index.json').read_text(encoding='utf-8')):
        if 'file' not in package:
            ignored.append(package)
            continue
        file = package['file']
        report = json.loads((folder / file).read_text(encoding='utf-8'))
        for suffix, key in (('.uasset', 'asset_sha256'), ('.uexp', 'body_sha256')):
            if hashlib.sha256((folder / file.replace('.json', suffix)).read_bytes()).hexdigest() != report[key]:
                raise ValueError('Changed UI source: ' + file)
        roots = [e for e in report['exports'] if e['type'] == 'WidgetBlueprintGeneratedClass']
        if not roots:
            ignored.append(dict(file=file, reason='No WidgetBlueprintGeneratedClass export; dependency path is not a root'))
            continue
        slots = defaultdict(list)
        for row in by_file[file]:
            slots[row['decoded']['content_export']].append(row)
        controls = []
        for export in report['exports']:
            if export['type'].endswith('Slot') or export['type'] in ('Function', 'WidgetBlueprintGeneratedClass') or export['name'].startswith('Default__'):
                continue
            chain, termination = parent_chain(export['index'], slots)
            controls.append(dict(export=export['index'], name=export['name'], type=export['type'],
                offset=export['offset'], size=export['size'], sha256=export['sha256'],
                local_slots=[r['provenance']['slot_export'] for r in slots[export['index']]],
                parent_chain=chain, chain_termination=termination))
            container = containers.get((file, export['index']))
            if container:
                if container['provenance']['sha256'] != export['sha256']:
                    raise ValueError('Container geometry changed: ' + file)
                controls[-1]['container_geometry'] = container
                if export['type'] == 'SizeBox':
                    controls[-1]['size_constraints'] = size_constraints(container['decoded'])
                controls[-1]['container_native_schema'] = container_schemas.get(export['type'])
            elif export['type'] in ('SizeBox', 'ScaleBox'):
                controls[-1]['container_geometry_unresolved'] = container_failures.get((file, export['index']), {}).get('error', export['type'] + ' not decoded')
        for root in roots:
            name = root['name'].removesuffix('_C')
            paths = sorted(set(p for p in report['paths'] if p.rsplit('/', 1)[-1] == name))
            catalog_file = file if len(roots) == 1 else file.replace('.json', '-root-' + str(root['index']) + '.json')
            window = dict(file=file, catalog_file=catalog_file, name=name, resource_paths=paths, root_export=root,
                source=report['source'], entry=report['entry'], asset_sha256=report['asset_sha256'],
                body_sha256=report['body_sha256'], popup=('Popup' in name or any('/MessageBox/' in p for p in paths)),
                controls=controls, decoded_slots=by_file[file], excluded_slots=failed_by_file[file],
                container_native_schema=container_schemas.get('SizeBox'), container_native_schemas=container_schemas,
                absolute_screen_geometry_verified=False,
                limitations=['Archetype/desired sizes/runtime DPI/visibility/animations unresolved',
                             'Byte size of export is not widget width or height',
                             'SizeBox constraints require both explicit value and enable flag; missing defaults unresolved',
                             'Dynamic localization/caller not implied by a similar resource name'])
            windows.append(window)
            for path in paths:
                resources[path].append(dict(file=catalog_file, source_file=file, body_sha256=report['body_sha256'], source=report['source']))
    out = ROOT / 'ui-catalog'
    out.mkdir(exist_ok=True)
    # One file per package avoids loading all UI geometry for a single lookup.
    for window in windows:
        (out / window['catalog_file']).write_text(json.dumps(window, ensure_ascii=False, indent=2), encoding='utf-8')
    index = dict(windows=[dict(file=w['catalog_file'], source_file=w['file'], name=w['name'], paths=w['resource_paths'], popup=w['popup'],
                controls=len(w['controls']), decoded_slots=len(w['decoded_slots']), excluded_slots=len(w['excluded_slots'])) for w in windows],
                resource_variants=dict(resources), ignored=ignored,
                selection='All discovered UI WBP references; archive variants retained, not assumed active on Android')
    (out / 'index.json').write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(windows=len(windows), unique_resources=len(resources),
                         popup_variants=sum(w['popup'] for w in windows), ignored=len(ignored),
                         controls=sum(len(w['controls']) for w in windows))))


if __name__ == '__main__':
    main()
