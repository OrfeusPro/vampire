"""Decode source-backed ScaleBox stretch, scale and inherited widget properties."""
import importlib.util
import json
import math
from pathlib import Path

spec = importlib.util.spec_from_file_location('scale_box_common', Path(__file__).with_name('decode-size-boxes.py'))
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)


def decode(data, fields, schema):
    reader = common.canvas.Reader(data)
    result = dict(explicit_properties={}, slots=None, incoming_slot=None)
    for index, zero in reader.header():
        if index < 4:
            name = fields[index]
            if name == 'UserSpecifiedScale':
                value = 0.0 if zero else reader.read('<f')
                if not math.isfinite(value) or not 0 <= value <= 1000000:
                    raise ValueError('Invalid user specified scale')
            else:
                value = 0 if zero else reader.read('<B')
                if name == 'IgnoreInheritedScale':
                    if value not in (0, 1):
                        raise ValueError('Invalid IgnoreInheritedScale bool')
                    value = bool(value)
                elif name == 'Stretch' and value not in {r['value'] for r in schema['scale_enums']['EStretch']}:
                    raise ValueError('Unsupported stretch enum')
                elif name == 'StretchDirection' and value not in {r['value'] for r in schema['scale_enums']['EStretchDirection']}:
                    raise ValueError('Unsupported stretch direction enum')
            result['explicit_properties'][name] = value
        elif index == 4:
            count = 0 if zero else reader.read('<i')
            if count not in (0, 1):
                raise ValueError('ScaleBox must have at most one child')
            result['slots'] = [reader.read('<i') for _ in range(count)]
        elif index == 5:
            result['incoming_slot'] = 0 if zero else reader.read('<i')
        else:
            name, value = common.widget.property_value(reader, index - 5, zero, schema)
            result.setdefault('inherited_properties', {})[name] = value
    if reader.read('<I') != 0 or reader.pos != len(data):
        raise ValueError('Unaccounted ScaleBox suffix')
    return result


def main():
    schema = json.loads((common.ROOT / 'code-clues/ui-properties.json').read_text(encoding='utf-8'))
    common.collect(schema, 'ScaleBox', decode, 'scale_box', 'scale-boxes.json')


if __name__ == '__main__':
    main()
