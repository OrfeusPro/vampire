"""Read explicit SizeBox dimensions and enable flags with native property evidence."""
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
spec = importlib.util.spec_from_file_location('size_box_reader', Path(__file__).with_name('decode-canvas-slots.py'))
canvas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canvas)
panel_spec = importlib.util.spec_from_file_location('size_box_slot_reader', Path(__file__).with_name('decode-panel-slots.py'))
panel = importlib.util.module_from_spec(panel_spec)
panel_spec.loader.exec_module(panel)
widget_spec = importlib.util.spec_from_file_location('inherited_widget_reader', Path(__file__).with_name('decode-widget-properties.py'))
widget = importlib.util.module_from_spec(widget_spec)
widget_spec.loader.exec_module(widget)


def decode(data, fields, widget_schema=None):
    reader = canvas.Reader(data)
    result = dict(explicit_properties={}, slots=None, incoming_slot=None)
    for index, zero in reader.header():
        if index < 16:
            if index >= 8:
                value = False if zero else reader.read('<B')
                if value not in (0, 1):
                    raise ValueError('Invalid SizeBox override bool')
                value = bool(value)
            else:
                value = 0.0 if zero else reader.read('<f')
                if not math.isfinite(value) or not 0 <= value <= 1000000:
                    raise ValueError('Invalid SizeBox dimension')
            result['explicit_properties'][fields[index]] = value
        elif index == 16:
            count = 0 if zero else reader.read('<i')
            if count not in (0, 1):
                raise ValueError('SizeBox must have at most one child slot')
            result['slots'] = [reader.read('<i') for _ in range(count)]
        elif index == 17:
            result['incoming_slot'] = 0 if zero else reader.read('<i')
        elif widget_schema and index > 17:
            name, value = widget.property_value(reader, index - 17, zero, widget_schema)
            result.setdefault('inherited_properties', {})[name] = value
        else:
            raise ValueError('Unresolved inherited SizeBox property: ' + str(index))
    if reader.read('<I') != 0 or reader.pos != len(data):
        raise ValueError('Unaccounted SizeBox suffix')
    return result


def collect(schema, kind='SizeBox', decoder=decode, schema_key='size_box', destination='size-boxes.json'):
    if hashlib.sha256(Path(schema['source']).read_bytes()).hexdigest() != schema['sha256']:
        raise ValueError('Native schema executable changed')
    fields = [p['name'] for p in schema[schema_key]['properties']]
    folder = ROOT / 'ui-layout-study'
    rows, failures = [], []
    for package in json.loads((folder / 'index.json').read_text(encoding='utf-8')):
        if 'file' not in package:
            continue
        report = json.loads((folder / package['file']).read_text(encoding='utf-8'))
        targets = [e for e in report['exports'] if e['type'] == kind]
        if not targets:
            continue
        body = (folder / package['file'].replace('.json', '.uexp')).read_bytes()
        if hashlib.sha256(body).hexdigest() != report['body_sha256']:
            raise ValueError('Changed widget source')
        header_size = (folder / package['file'].replace('.json', '.uasset')).stat().st_size
        exports = {e['index']: e for e in report['exports']}
        for export in targets:
            provenance = dict(file=package['file'], export=export['index'], name=export['name'], offset=export['offset'],
                              sha256=export['sha256'], source=report['source'], entry=report['entry'])
            try:
                start = export['offset'] - header_size
                raw = body[start:start + export['size']]
                if hashlib.sha256(raw).hexdigest() != export['sha256']:
                    raise ValueError('Changed ' + kind + ' export')
                result = decoder(raw, fields, schema)
                for slot in result['slots'] or []:
                    if slot not in exports or exports[slot]['type'] != kind + 'Slot':
                        raise ValueError(kind + ' child reference mismatch')
                    checked = panel.Reader(bytes.fromhex(exports[slot]['serialized_hex'])).panel_slot(kind + 'Slot')
                    if checked.get('parent_export') != export['index'] or checked.get('content_export') not in exports:
                        raise ValueError(kind + ' slot Parent/Content mismatch')
                incoming = result['incoming_slot']
                if incoming and (incoming not in exports or not exports[incoming]['type'].endswith('Slot')):
                    raise ValueError('Incoming slot reference mismatch')
                rows.append(dict(provenance=provenance, decoded=result))
            except (ValueError, KeyError) as error:
                failures.append(dict(provenance=provenance, error=str(error)))
    dest = ROOT / 'ui-geometry' / destination
    dest.write_text(json.dumps(dict(native_schema=dict(source=schema['source'], sha256=schema['sha256'],
        array_offset=schema[schema_key]['array_offset'], widget_array_offset=schema['widget']['array_offset'],
        widget_transform_array_offset=schema['widget_transform']['array_offset']), container_kind=kind, boxes=rows, failures=failures,
        absolute_screen_geometry_verified=False,
        limitations=['Only explicitly serialized values; omitted properties and archetype defaults remain unknown',
                     ('Float value alone does not enable override; bOverride flag must be considered' if kind == 'SizeBox'
                      else 'UserSpecifiedScale is not applied unless the Stretch mode requires it'),
                     'Desired size, DPI, runtime mutations, inherited layout and visibility unresolved']), ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(decoded=len(rows), failures=len(failures), examples=failures[:2])))


def main():
    schema = json.loads((ROOT / 'code-clues/ui-properties.json').read_text(encoding='utf-8'))
    collect(schema)


if __name__ == '__main__':
    main()
