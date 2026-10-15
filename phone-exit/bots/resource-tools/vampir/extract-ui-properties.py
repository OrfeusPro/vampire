"""Recover native UI property descriptor arrays, without guessing name order."""
import hashlib
import importlib.util
import json
import os
import re
import struct
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
spec = importlib.util.spec_from_file_location('native_pe', Path(__file__).with_name('extract-native-enums.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
FIELDS = ['WidthOverride', 'HeightOverride', 'MinDesiredWidth', 'MinDesiredHeight',
          'MaxDesiredWidth', 'MaxDesiredHeight', 'MinAspectRatio', 'MaxAspectRatio']
FIELDS += ['bOverride_' + name for name in FIELDS[:]]
WIDGET_FIELDS = ['Slot', 'bIsEnabledDelegate', 'ToolTipTextDelegate', 'ToolTipText', 'ToolTipWidget',
    'ToolTipWidgetDelegate', 'VisibilityDelegate', 'RenderTransform', 'RenderTransformPivot',
    'UnderlyingType', 'FlowDirectionPreference', 'bIsVariable', 'bCreatedByConstructionScript',
    'bIsEnabled', 'bOverride_Cursor', 'bIsVolatile', 'Cursor', 'UnderlyingType', 'Clipping',
    'UnderlyingType', 'Visibility', 'UnderlyingType', 'PixelSnapping', 'RenderOpacity',
    'AccessibleWidgetData', 'Navigation', 'NativeBindings', 'NativeBindings']
WIDGET_FLAGS = [82, 26, 26, 29, 82, 26, 26, 25, 25, 0, 30, 12, 12, 12, 12, 12, 0, 0, 30,
                0, 30, 0, 30, 10, 82, 82, 82, 22]


def extract(data, expected_fields=None, expected_flags=None, anchor_index=0):
    pe = native.PE(data)
    expected_fields = FIELDS if expected_fields is None else expected_fields
    expected_flags = [10 if i < 8 else 12 for i in range(len(expected_fields))] if expected_flags is None else expected_flags

    def offset(address):
        for section in pe.sections:
            delta = address - pe.base - section['rva']
            if 0 <= delta < section['raw_size']:
                return section['raw'] + delta
        return None

    def references(address):
        target = struct.pack('<Q', address)
        hits = []
        for section in pe.sections:
            if section['name'] not in ('.rdata', '.data'):
                continue
            start = section['raw']
            for match in re.finditer(re.escape(target), data[start:start + section['raw_size']]):
                pos = start + match.start()
                if pos % 8 == 0:
                    hits.append(pos)
        return hits

    candidates = []
    for match in re.finditer(rb'(?<![A-Za-z0-9_])' + re.escape(expected_fields[anchor_index].encode()) + rb'\x00', data):
        address = pe.address(match.start())
        if address is None:
            continue
        for descriptor in references(address):
            for anchor_pointer in references(pe.address(descriptor)):
                array = anchor_pointer - anchor_index * 8
                if array < 0:
                    continue
                rows = []
                for i, expected in enumerate(expected_fields):
                    position = array + i * 8
                    if position + 8 > len(data):
                        break
                    prop = offset(struct.unpack_from('<Q', data, position)[0])
                    if prop is None or prop + 32 > len(data):
                        break
                    name = offset(struct.unpack_from('<Q', data, prop)[0])
                    if name is None or data[name:name + len(expected) + 1] != expected.encode() + b'\0':
                        break
                    flags = struct.unpack_from('<I', data, prop + 24)[0]
                    if flags & 255 != expected_flags[i]:
                        break
                    rows.append(dict(index=i, name=expected, name_offset=name, descriptor_offset=prop,
                        pointer_offset=position, gen_flags=flags, descriptor_prefix_hex=data[prop:prop + 32].hex()))
                if len(rows) == len(expected_fields):
                    candidates.append(dict(array_offset=array, properties=rows))
    if len(candidates) != 1:
        raise ValueError('Expected one complete native property array; found ' + str(len(candidates)))
    return candidates[0]


def main():
    enums = json.loads((ROOT / 'code-clues/native-enums.json').read_text(encoding='utf-8'))
    data = Path(enums['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != enums['sha256']:
        raise ValueError('Executable changed; rebuild source evidence')
    found = extract(data)
    widget = extract(data, WIDGET_FIELDS, WIDGET_FLAGS, anchor_index=7)
    # These entries describe nested enum/array children, not standalone fields.
    nested = {9, 17, 19, 21, 26}
    widget['serialized_properties'] = [dict(row, schema_index=index) for index, row in enumerate(
        row for row in widget['properties'] if row['index'] not in nested)]
    widget['nested_descriptor_indices'] = sorted(nested)
    transform = extract(data, ['Translation', 'Scale', 'Shear', 'Angle'], [25, 25, 25, 10], anchor_index=2)
    scale = extract(data, ['Stretch', 'StretchDirection', 'UserSpecifiedScale', 'IgnoreInheritedScale'], [0, 0, 10, 76], anchor_index=2)
    report = dict(source=enums['source'], sha256=enums['sha256'], size_box=found, widget=widget, widget_transform=transform, scale_box=scale,
        scale_enums={name: enums['enums'][name] for name in ('EStretch', 'EStretchDirection')},
        evidence='Native array pointers to named property descriptors; not string order',
        limitation='Native property family proven; cooked class association checked by type and byte parsing, no C++ source available')
    (ROOT / 'code-clues/ui-properties.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(dict(properties=len(found['properties']), array_offset=found['array_offset'],
                         widget_properties=len(widget['serialized_properties']), widget_array=widget['array_offset'],
                         transform_array=transform['array_offset'], scale_box_array=scale['array_offset'])))


if __name__ == '__main__':
    main()
