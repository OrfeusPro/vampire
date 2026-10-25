"""Verify current Image/WidgetTree metadata and scan source roots without runtime promotion."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ui_pipeline as cache
from ui_widget_tree import decode_root


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


basic = load('root_basic_native', 'decode-basic-slot-candidates.py')
scopes = load('root_scope_verifier', 'scan-ui-outer-scopes.py')
references = load('root_package_references', 'decode-package-references.py')
SPECS = {
    'WidgetTree': dict(getter=0x1435f6360, metadata=0x149010380, array=0x1490101f0,
        fields=['RootWidget', 'NamedSlotBindings', 'NamedSlotBindings_Key', 'NamedSlotBindings'], flags=[82, 82, 20, 23]),
    'Image': dict(getter=0x14357fc60, metadata=0x148fdfbe0, array=0x148fdf820,
        fields=['Brush', 'BrushDelegate', 'ColorAndOpacity', 'ColorAndOpacityDelegate',
                'bFlipForRightToLeftFlowDirection', 'OnMouseButtonDownEvent'], flags=[25, 26, 25, 26, 76, 26])
}


def native_schema(request_path):
    request = json.loads(request_path.read_bytes())
    if request['source_sha256'] != basic.SHA:
        raise ValueError('Unreviewed native source')
    roots = {int(row['address'], 16) for row in request['functions']}
    if not {s['getter'] for s in SPECS.values()} <= roots:
        raise ValueError('Missing explicit getter request')
    raw = basic.source.checked(Path(request['source']), basic.SHA)
    image = basic.native.Image(raw)
    ranges = set()
    for spec in SPECS.values():
        address = spec['getter']
        item = image.containing(address)
        if item is None or image.pe.base + image.roots[item][0] != address:
            raise ValueError('Getter unwind root differs')
        ranges.add(image.roots[item])
    fragments = basic.native.decode_ranges(image, ranges)
    result = {}
    for kind, spec in SPECS.items():
        pos = image.offset(spec['metadata'] - image.pe.base)
        block = raw[pos:pos + 64]
        if struct.unpack_from('<Q', block)[0] != spec['getter'] or struct.unpack_from('<Q', block, 40)[0] != spec['array']:
            raise ValueError('Metadata getter/array differs')
        fragment = next(f for f in fragments if f['instructions'][0]['address'] == spec['getter'])
        refs = {r for ins in fragment['instructions'] for r in ins['rip_references']}
        literals = {}
        for text in [kind, '/Script/UMG']:
            expected = text.encode('utf-16le') + b'\0\0'
            hits = []
            for address in refs:
                try:
                    at = image.offset(address - image.pe.base)
                except ValueError:
                    # Cache globals can be in zero-filled sections, unlike literals.
                    continue
                if raw[at:at + len(expected)] == expected:
                    hits.append(hex(address))
            if len(hits) != 1:
                raise ValueError('Getter class/package literal differs')
            literals[text] = hits[0]
        rows = []
        for i, (name, flag) in enumerate(zip(spec['fields'], spec['flags'])):
            array_pos = image.offset(spec['array'] - image.pe.base) + i * 8
            descriptor = struct.unpack_from('<Q', raw, array_pos)[0]
            at = image.offset(descriptor - image.pe.base)
            pointer = struct.unpack_from('<Q', raw, at)[0]
            text_pos = image.offset(pointer - image.pe.base)
            flags = struct.unpack_from('<I', raw, at + 24)[0]
            if raw[text_pos:text_pos + len(name) + 1] != name.encode() + b'\0' or flags & 255 != flag:
                raise ValueError('Property descriptor differs')
            rows.append(dict(array_index=i, name=name, gen_flags=flags, descriptor=hex(descriptor),
                             prefix_hex=raw[at:at + 64].hex()))
        result[kind] = dict(getter=hex(spec['getter']), metadata=hex(spec['metadata']),
            metadata_hex=block.hex(), property_array=hex(spec['array']), descriptors=rows,
            literals=literals, fragment=fragment)
    return dict(source_sha256=basic.SHA, classes=result, native_executed=False,
                limits=['Descriptor rows include map children; they are not all standalone serialized fields.',
                        'Only explicit WidgetTree index zero is read; Brush structs and defaults remain undecoded.'])


def build(root, scope_folder, request_path, output):
    proof = native_schema(request_path)
    scopes.verify(root, scope_folder)
    index = json.loads((scope_folder / 'index.json').read_bytes())
    records, containers, totals = [], [], Counter()
    for pid, package in sorted(index['packages'].items()):
        stem = Path(package['source_file']).stem
        asset = basic.source.checked(root / 'ui-layout-study' / (stem + '.uasset'), package['asset_sha256'])
        body = basic.source.checked(root / 'ui-layout-study' / (stem + '.uexp'), package['body_sha256'])
        parsed = basic.source.inspector.exports(asset, body)
        exports = {e['index']: e for e in parsed['exports']}
        targets = [e for e in exports.values() if e['type'] == 'WidgetTree']
        refs = references.references(asset, parsed)['references'] if targets else {}
        ownership = json.loads((scope_folder / package['ref']).read_bytes())
        for entry in exports.values():
            if entry['type'] != 'NamedSlot':
                continue
            cls = refs[entry['index']]['class_index']
            if refs[cls]['path'] != '/Script/UMG.NamedSlot' or exports[entry['outer']]['type'] != 'WidgetTree':
                raise ValueError('Unreviewed NamedSlot import / owner')
            at = entry['offset'] - len(asset)
            payload = body[at:at + entry['size']]
            if basic.sha(payload) != entry['sha256']:
                raise ValueError('NamedSlot source bytes differ')
            containers.append(dict(source_file=package['source_file'], export=entry,
                asset_sha256=package['asset_sha256'], body_sha256=package['body_sha256'],
                source_owner_root=ownership['exports'][str(entry['index'])]['owner_root'],
                imported_class=refs[cls]['path'], raw_hex=payload.hex(),
                classification='imported_named_slot_container_candidate',
                inherited_properties_decoded=False, geometry_verified=False))
        for entry in targets:
            at = entry['offset'] - len(asset)
            raw = body[at:at + entry['size']]
            if basic.sha(raw) != entry['sha256']:
                raise ValueError('WidgetTree source bytes differ')
            row = dict(package=pid, source_file=package['source_file'], export=entry,
                       asset_sha256=package['asset_sha256'], body_sha256=package['body_sha256'],
                       runtime_root=None, geometry_verified=False, cooked_current_compatibility_verified=False)
            try:
                cls = refs[entry['index']]['class_index']
                if refs[cls]['path'] != '/Script/UMG.WidgetTree':
                    raise ValueError('Unreviewed WidgetTree class import')
                row['decoded'] = decode_root(raw)
                target = row['decoded']['explicit_root_widget']
                owner = ownership['exports'][str(entry['index'])]['owner_root']
                row['source_owner_root'] = owner
                if target is not None and target > 0:
                    node = exports.get(target)
                    if node is None or node['outer'] != entry['index'] or ownership['exports'][str(target)]['owner_root'] != owner:
                        raise ValueError('RootWidget target is outside its source WidgetTree')
                    row['source_root_widget'] = node
                    row['status'] = 'explicit_local_root_candidate'
                else:
                    row['status'] = 'omitted_or_null_or_external_root'
            except (ValueError, KeyError) as error:
                row['status'] = 'requires_review'
                row['unknown'] = str(error)
                row['raw_hex'] = raw.hex()
            totals[row['status']] += 1
            records.append(row)
    result = dict(schema=1, kind='source_widget_tree_roots', native=proof, records=records,
        container_candidates=containers, statistics=dict(totals, named_slot_candidates=len(containers)),
        inputs=dict(scope_index_sha256=cache.sha(scope_folder / 'index.json'), request_sha256=cache.sha(request_path)),
        tools={p.name: cache.sha(p) for p in [Path(__file__), HERE / 'ui_widget_tree.py', HERE / 'decode-canvas-slots.py',
               HERE / 'decode-package-references.py', HERE / 'inspect-ui.py', HERE / 'build-native-entry-code.py']},
        limits=['RootWidget is serialized source structure, not the visible game window or runtime variant.',
                'NamedSlot import / source owner identify a container candidate; inherited fields remain opaque.',
                'Current native/cooked compatibility, inheritance, visibility, bindings, DPI and Brush remain open.'])
    identity = basic.sha(cache.encoded(result))
    folder = output / identity
    folder.mkdir(parents=True, exist_ok=True)
    destination = folder / 'index.json'
    if destination.exists() and destination.read_bytes() != cache.encoded(result):
        raise ValueError('Published root scan differs')
    if not destination.exists():
        with destination.open('xb') as stream:
            stream.write(cache.encoded(result))
    return dict(output=str(folder), dataset_id=identity, **result['statistics'])


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    p.add_argument('--scopes', type=Path, required=True)
    p.add_argument('--request', type=Path, required=True)
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    out = (a.output or a.root / 'ui-property-scans/widget-roots').resolve()
    if any(out.is_relative_to(t.resolve()) for t in [HERE.parents[3], a.scopes, a.root / 'ui-catalog', a.root / 'ui-layout-study', a.root / 'maps/ui-prototype']):
        p.error('Keep results outside source/repository/snapshot folders')
    print(json.dumps(build(a.root, a.scopes, a.request, out), ensure_ascii=False))
