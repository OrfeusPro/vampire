"""Read explicit inherited widget fields using recovered native property order."""
import math


def finite(value):
    values = value if isinstance(value, list) else [value]
    if not all(math.isfinite(v) and abs(v) <= 1000000 for v in values):
        raise ValueError('Nonfinite or unbounded widget transform')
    return value


def property_value(reader, index, zero, schema):
    fields = schema['widget']['serialized_properties']
    if index < 0 or index >= len(fields):
        raise ValueError('Unknown inherited widget property: ' + str(index))
    field = fields[index]
    name, flags = field['name'], field['gen_flags'] & 255
    if name == 'RenderTransform':
        if zero:
            return name, dict(serialized_zero=True)
        result = dict(explicit_properties={})
        transform = schema['widget_transform']['properties']
        for part, is_zero in reader.header():
            if part >= len(transform):
                raise ValueError('Unknown WidgetTransform field')
            member = transform[part]
            is_angle = member['name'] == 'Angle'
            value = (0.0 if is_angle else [0.0, 0.0]) if is_zero else reader.read('<f' if is_angle else '<dd')
            result['explicit_properties'][member['name']] = finite(value)
        return name, result
    if name == 'RenderTransformPivot':
        return name, [0.0, 0.0] if zero else finite(reader.read('<dd'))
    if flags == 12:
        value = 0 if zero else reader.read('<B')
        if value not in (0, 1):
            raise ValueError('Invalid inherited widget bool')
        return name, bool(value)
    if flags in (0, 30):
        return name, 0 if zero else reader.read('<B')
    if name == 'RenderOpacity':
        value = 0.0 if zero else finite(reader.read('<f'))
        if not 0 <= value <= 1:
            raise ValueError('Widget opacity outside supported range')
        return name, value
    if flags == 82:
        return name, 0 if zero else reader.read('<i')
    if name == 'NativeBindings':
        count = 0 if zero else reader.read('<i')
        if count != 0:
            raise ValueError('Nonempty native bindings not decoded')
        return name, []
    if zero:
        return name, dict(serialized_zero=True)
    raise ValueError('Unsupported explicit inherited widget field: ' + name)
