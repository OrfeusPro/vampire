"""Decode an observed named-slot-shaped prefix; keep class ordinal unproven."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


canvas = load('named_slot_reader', 'decode-canvas-slots.py')
props = load('named_slot_properties', 'extract-ui-properties.py')
native = load('named_slot_code', 'build-native-entry-code.py')
ROOT = native.ROOT


def decode_observed_prefix(raw, names):
    reader = canvas.Reader(raw)
    header = reader.header()
    if header != [(59, False), (68, False)]:
        raise ValueError('Unreviewed instance property indices')
    count = reader.read('<i')
    if not 0 <= count <= 64:
        raise ValueError('Unbounded binding count')
    bindings = []
    for _ in range(count):
        if reader.header() != [(0, False), (1, False)]:
            raise ValueError('Unreviewed Name/Content struct header')
        name_index, number = reader.read('<ii')
        if not 0 <= name_index < len(names) or number != 0:
            raise ValueError('Invalid or unsupported slot FName')
        content = reader.read('<i')
        if content <= 0:
            raise ValueError('Binding content is not a local export')
        bindings.append(dict(name_index=name_index, name=names[name_index], number=number,
                             content_export=content))
    parent_slot = reader.read('<i')
    if parent_slot <= 0:
        raise ValueError('Instance slot is not a local export')
    return dict(header=header, observed_bindings=bindings, observed_slot_reference=parent_slot,
                consumed_bytes=reader.pos, opaque_tail=raw[reader.pos:].hex(),
                class_property_ordinal_verified=False, whole_export_decoded=False)


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    source = json.loads((ROOT / 'code-clues/native-enums.json').read_text(encoding='utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native executable changed')
    schema = props.extract(data, ['Name', 'Content'], [20, 82])
    array_property = props.extract(data, ['NamedSlotBindings'], [22])
    image = native.Image(data)
    child_pointer = array_property['array_offset'] - 8
    child = image.offset(struct.unpack_from('<Q', data, child_pointer)[0] - image.pe.base)
    if (struct.unpack_from('<I', data, child + 24)[0] & 255 != 25 or
            struct.unpack_from('<Q', data, child + 56)[0] != 0x1435f0010):
        raise ValueError('NamedSlotBindings inner struct changed')
    fragments = native.decode_ranges(image, {image.roots[image.containing(0x1435f0010)]})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    if rows[0x1435f0020]['rip_references'] != [0x14b09f158]:
        raise ValueError('NamedSlotBinding struct metadata changed')
    metadata = image.offset(0x14b09f158 - image.pe.base)
    name_pointer, fields_pointer = struct.unpack_from('<QQ', data, metadata + 24)
    name_offset = image.offset(name_pointer - image.pe.base)
    if data[name_offset:name_offset + 17] != b'NamedSlotBinding\0':
        raise ValueError('Named struct type changed')
    if fields_pointer != image.pe.address(schema['array_offset']):
        raise ValueError('Struct fields do not match Name/Content schema')
    records = []
    for filename in ('pakchunk500-Windows-575.json', 'ProjectRED-Windows-7883.json'):
        layout = json.loads((ROOT / 'ui-layout-study' / filename).read_text(encoding='utf-8'))
        catalog = json.loads((ROOT / 'ui-catalog' / filename).read_text(encoding='utf-8'))
        asset = (ROOT / 'ui-layout-study' / filename.replace('.json', '.uasset')).read_bytes()
        body = (ROOT / 'ui-layout-study' / filename.replace('.json', '.uexp')).read_bytes()
        if (hashlib.sha256(asset).hexdigest() != layout['asset_sha256'] or
                hashlib.sha256(body).hexdigest() != layout['body_sha256']):
            raise ValueError('Cooked variant changed')
        exports = {e['index']: e for e in layout['exports']}
        item = next(e for e in exports.values() if e['name'] == 'CommonMessageNotifyLightUI')
        raw = (asset + body)[item['offset']:item['offset'] + item['size']]
        if hashlib.sha256(raw).hexdigest() != item['sha256']:
            raise ValueError('Instance export changed')
        result = decode_observed_prefix(raw, layout['names'])
        if len(result['observed_bindings']) != 1:
            raise ValueError('Reviewed single binding changed')
        binding = result['observed_bindings'][0]
        target = exports[binding['content_export']]
        if (binding['name'] != 'NamedSlotContent' or target['name'] != 'TextMessage' or
                target['type'] != 'NkRichTextBlock'):
            raise ValueError('Observed named content changed')
        slot = next(s for s in catalog['decoded_slots']
                    if s['provenance']['slot_export'] == result['observed_slot_reference'])
        if slot['decoded']['content_export'] != item['index']:
            raise ValueError('Instance slot back-reference differs')
        records.append(dict(file=filename, source=layout['source'], entry=layout['entry'],
                            asset_sha256=layout['asset_sha256'], body_sha256=layout['body_sha256'],
                            export=item, prefix=result, content_export=target, instance_slot=slot))
    report = dict(source=source['source'], sha256=source['sha256'], schema=schema,
                  array_property=array_property, struct_fragments=fragments,
                  struct_metadata=dict(address=0x14b09f158, file_offset=metadata,
                                       bytes=data[metadata:metadata + 48].hex()),
                  inner_property=dict(file_offset=child, bytes=data[child:child + 64].hex()),
                  records=records, class_property_ordinal_verified=False,
                  runtime_layout_enabled=False,
                  limitations=['Struct Name/Content and NamedSlotBindings inner type are proven.',
                               'Property59 association still needs full NkUserWidget/UserWidget inheritance schema.',
                               'Observed value prefix is not yet an authoritative topology edge.',
                               'Four trailing bytes are opaque; no absolute geometry or Android claim.'])
    output = ROOT / 'ui-geometry/system-message-named-slot.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(variants=len(records), native_struct='NamedSlotBinding',
                          content='TextMessage', class_property_ordinal_verified=False,
                          runtime_layout_enabled=False)))


if __name__ == '__main__':
    main()
