"""Source-bound NamedSlot inheritance candidates; never apply defaults or renderer geometry."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ui_named_slot
import ui_pipeline as cache

spec = importlib.util.spec_from_file_location('named_native_basic', HERE / 'decode-basic-slot-candidates.py')
basic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(basic)

SPECS = {
    'NamedSlot': (0x143579140, 0x148fd58e0, 0x143579140, 0, 0x14356aad0),
    'ContentWidget': (0x1435b5080, 0x148fdfd10, 0x14356aad0, 0, 0x14356ab10),
    'PanelWidget': (0x1435b5290, 0x148fe4270, 0x14356ab10, 0x148fe4108, 0x14356ab30),
    'Widget': (0x1435b5340, 0x148ff1590, 0x14356ab30, 0x148ff0c00, 0x14357d570),
    'Visual': (0x14357d570, 0x148fed900, 0x14357d570, 0, 0x141621180),
}


def native_schema(request):
    req = json.loads(request.read_bytes())
    if req['source_sha256'] != basic.SHA or req['question'] != 'ui-named-slot-inheritance-11316':
        raise ValueError('Unreviewed NamedSlot native request')
    if not {s[0] for s in SPECS.values()} <= {int(f['address'], 16) for f in req['functions']}:
        raise ValueError('Missing explicit class getter roots')
    raw = basic.source.checked(Path(req['source']), basic.SHA)
    image = basic.native.Image(raw)
    ranges = set()
    for getter, *_ in SPECS.values():
        index = image.containing(getter)
        if index is None or image.pe.base + image.roots[index][0] != getter:
            raise ValueError('Class getter unwind boundary differs')
        ranges.add(image.roots[index])
    fragments = basic.native.decode_ranges(image, ranges)
    proof = {}
    for name, (getter, metadata, class_pointer, array, parent) in SPECS.items():
        fragment = next(f for f in fragments if f['instructions'][0]['address'] == getter)
        instructions = fragment['instructions']
        refs = {r for i in instructions for r in i['rip_references']}
        if parent not in refs or sum(i['direct_target'] == 0x1416ab8d0 for i in instructions) != 1:
            raise ValueError('Registration / parent callback flow differs')
        if [i['bytes'] for i in instructions[:2]] != ['4c8bdc', '4883ec78']:
            raise ValueError('Getter stack frame differs')
        if not any(parent in i['rip_references'] and any(j['bytes'] == '498943e8' for j in instructions[n+1:n+4])
                   for n, i in enumerate(instructions)):
            raise ValueError('Parent callback is not stored in argument 13')
        for literal in (name, '/Script/UMG'):
            expected = literal.encode('utf-16le') + b'\0\0'
            found = False
            for address in refs:
                try:
                    at = image.offset(address - image.pe.base)
                except ValueError:
                    continue
                found |= raw[at:at + len(expected)] == expected
            if not found:
                raise ValueError('Class / package literal differs')
        at = image.offset(metadata - image.pe.base)
        block = raw[at:at + 64]
        if struct.unpack_from('<Q', block)[0] != class_pointer or struct.unpack_from('<Q', block, 40)[0] != array:
            raise ValueError('Metadata getter / property array differs')
        thunk = None
        if class_pointer != getter:
            pos = image.offset(class_pointer - image.pe.base)
            code = raw[pos:pos + 5]
            if code[:1] != b'\xe9' or class_pointer + 5 + struct.unpack_from('<i', code, 1)[0] != getter:
                raise ValueError('Metadata getter thunk differs')
            thunk = dict(address=hex(class_pointer), bytes=code.hex(), target=hex(getter))
        fields = [('Slots', 82), ('Slots', 22)] if name == 'PanelWidget' else (
            list(zip(basic.props.WIDGET_FIELDS, basic.props.WIDGET_FLAGS)) if name == 'Widget' else [])
        rows = []
        for index, (field_name, flag) in enumerate(fields):
            pointer = struct.unpack_from('<Q', raw, image.offset(array - image.pe.base) + index * 8)[0]
            pos = image.offset(pointer - image.pe.base)
            string = image.offset(struct.unpack_from('<Q', raw, pos)[0] - image.pe.base)
            if raw[string:string + len(field_name) + 1] != field_name.encode() + b'\0' or struct.unpack_from('<I', raw, pos + 24)[0] & 255 != flag:
                raise ValueError('Named property descriptor differs')
            rows.append(dict(name=field_name, flag=flag, descriptor=hex(pointer), bytes=raw[pos:pos + 64].hex()))
        proof[name] = dict(getter=hex(getter), metadata=hex(metadata), metadata_hex=block.hex(),
            parent_callback=hex(parent), thunk=thunk, property_array=hex(array), descriptors=rows, fragment=fragment)
    schema = [dict(name='Slots', reader='object_array', source='PanelWidget', descriptor_index=1)]
    nested = {9, 17, 19, 21, 26}
    for index, row in enumerate(proof['Widget']['descriptors']):
        if index in nested:
            continue
        name = row['name']
        schema.append(dict(name=name, reader={'Slot': 'object', 'bIsVariable': 'bool'}.get(name, 'unreviewed'),
                           source='Widget', descriptor_index=index))
    return dict(source_sha256=basic.SHA, classes=proof, candidate_ordinal_schema=schema,
        nested_widget_descriptor_indices=sorted(nested), native_executed=False,
        schema_status='candidate_static_parent_callback_order',
        limits=['Generic class/property construction and inherited serializer order not executed.',
                'No CDO/archetype/defaults, cooked/current compatibility or runtime geometry established.',
                'Visual parent callback beyond this boundary is not inspected.'])


def build(root, roots_path, roots_sha, request, output):
    roots = json.loads(basic.source.checked(roots_path, roots_sha))
    if roots.get('kind') != 'source_widget_tree_roots' or roots.get('schema') != 1:
        raise ValueError('Expected source WidgetTree report')
    proof = native_schema(request)
    inputs = {str(roots_path): roots_sha, str(request): cache.sha(request)}
    records, totals, packages = [], Counter(), {}
    for candidate in roots['container_candidates']:
        if candidate['imported_class'] != '/Script/UMG.NamedSlot':
            raise ValueError('Unreviewed imported container')
        source = candidate['source_file']
        if source not in packages:
            stem = Path(source).stem
            paths = [root / 'ui-layout-study' / (stem + ext) for ext in ('.uasset', '.uexp')]
            asset = basic.source.checked(paths[0], candidate['asset_sha256'])
            body = basic.source.checked(paths[1], candidate['body_sha256'])
            inputs.update({str(p): cache.sha(p) for p in paths})
            parsed = basic.source.inspector.exports(asset, body)
            catalog_path = root / 'ui-catalog' / source
            catalog = json.loads(catalog_path.read_bytes())
            if (catalog['asset_sha256'], catalog['body_sha256']) != (candidate['asset_sha256'], candidate['body_sha256']):
                raise ValueError('Source catalog differs')
            inputs[str(catalog_path)] = cache.sha(catalog_path)
            packages[source] = (asset, body, {e['index']: e for e in parsed['exports']},
                {s['provenance']['slot_export']: s['decoded'] for s in catalog['decoded_slots']})
        asset, body, exports, slots = packages[source]
        entry = exports[candidate['export']['index']]
        if entry != candidate['export'] or entry['type'] != 'NamedSlot':
            raise ValueError('NamedSlot export differs')
        at = entry['offset'] - len(asset)
        raw = body[at:at + entry['size']]
        if basic.sha(raw) != entry['sha256'] or raw.hex() != candidate['raw_hex']:
            raise ValueError('NamedSlot payload differs')
        row = dict(source_file=source, export=entry, asset_sha256=candidate['asset_sha256'],
            body_sha256=candidate['body_sha256'], raw_hex=raw.hex(), geometry_verified=False)
        try:
            value = ui_named_slot.decode(raw, proof['candidate_ordinal_schema'])
            links = []
            properties = value['candidate_explicit_properties']
            for kind, targets in [('Slot', [properties['Slot']] if properties.get('Slot') else []),
                                  ('Slots', properties.get('Slots', []))]:
                for target in targets:
                    item = exports.get(target)
                    if item is None or not item['type'].endswith('Slot') or item['type'] == 'NamedSlot':
                        raise ValueError('Candidate reference is not a local slot export')
                    relation = slots.get(target)
                    if relation is not None and relation['content_export' if kind == 'Slot' else 'parent_export'] != entry['index']:
                        raise ValueError('Candidate NamedSlot link contradicts decoded source relation')
                    links.append(dict(field=kind, target=item, decoded_source_relation=relation,
                        status='source_decoded_relation' if relation is not None else 'source_slot_type_candidate_only'))
            row.update(status='candidate_parse_complete', decoded=value, candidate_links=links)
            totals.update(parsed=1, explicit_fields=len(properties), links=len(links))
        except (ValueError, KeyError) as error:
            row.update(status='requires_review', error=str(error))
            totals.update(requires_review=1)
        records.append(row)
    result = dict(schema=1, kind='named_slot_inherited_candidates', native=proof, inputs=inputs,
        records=records, statistics=dict(totals, instances=len(records)), renderer_allowed=False,
        tools={p.name: cache.sha(p) for p in [Path(__file__), HERE / 'ui_named_slot.py', HERE / 'decode-basic-slot-candidates.py',
            HERE / 'decode-canvas-slots.py', HERE / 'extract-ui-properties.py', HERE / 'extract-native-enums.py',
            HERE / 'build-native-entry-code.py', HERE / 'inspect-ui.py']})
    identity = basic.sha(cache.encoded(result))
    folder = output / identity
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / 'index.json'
    data = cache.encoded(result)
    if path.exists() and path.read_bytes() != data:
        raise ValueError('Published NamedSlot evidence differs')
    if not path.exists():
        with path.open('xb') as stream:
            stream.write(data)
    return dict(output=str(path), sha256=identity, **result['statistics'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--roots', type=Path, required=True)
    parser.add_argument('--roots-sha256', required=True)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(HERE.parents[3]):
        parser.error('Keep analysis evidence outside the repository')
    print(json.dumps(build(args.root, args.roots, args.roots_sha256, args.request, args.output), ensure_ascii=False))
