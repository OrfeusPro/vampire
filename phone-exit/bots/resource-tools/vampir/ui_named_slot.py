"""Bounded candidate value reader. The caller supplies the source-bound ordinal schema."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('named_slot_header_reader', Path(__file__).with_name('decode-canvas-slots.py'))
headers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(headers)


def decode(raw, schema):
    reader = headers.Reader(raw)
    fields = reader.header()
    header_size = reader.pos
    values, zeroes = {}, []
    for index, zero in fields:
        if not 0 <= index < len(schema):
            raise ValueError('NamedSlot ordinal outside supplied schema')
        field = schema[index]
        name, kind = field['name'], field['reader']
        if name in values:
            raise ValueError('Repeated NamedSlot property')
        if kind == 'object':
            value = 0 if zero else reader.read('<i')
            if value < 0:
                raise ValueError('External NamedSlot object reference requires review')
        elif kind == 'object_array':
            count = 0 if zero else reader.read('<i')
            if not 0 <= count <= 1024 or count > (len(raw) - reader.pos) // 4:
                raise ValueError('Invalid NamedSlot object array')
            value = [reader.read('<i') for _ in range(count)]
            if any(v <= 0 for v in value) or len(set(value)) != len(value):
                raise ValueError('Invalid / repeated local NamedSlot array reference')
        elif kind == 'bool':
            value = 0 if zero else reader.read('<B')
            if value not in (0, 1):
                raise ValueError('Invalid NamedSlot bool')
            value = bool(value)
        else:
            raise ValueError('Unreviewed explicit NamedSlot property reader: ' + name)
        values[name] = value
        if zero:
            zeroes.append(name)
    if reader.read('<I') != 0 or reader.pos != len(raw):
        raise ValueError('Unaccounted NamedSlot suffix / trailing bytes')
    return dict(candidate_explicit_properties=values, serialized_fields=fields,
        serialized_zero_fields=zeroes, omitted_properties=[f['name'] for f in schema if f['name'] not in values],
        header_hex=raw[:header_size].hex(), defaults_applied=False,
        inheritance_order_runtime_verified=False, geometry_verified=False)
