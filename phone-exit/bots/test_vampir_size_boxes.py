import importlib.util
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


properties = load('ui_properties_test', HERE / 'resource-tools/vampir/extract-ui-properties.py')
sizes = load('size_boxes_test', HERE / 'resource-tools/vampir/decode-size-boxes.py')
scales = load('scale_boxes_test', HERE / 'resource-tools/vampir/decode-scale-boxes.py')
pe_fixture = load('pe_fixture_test', HERE / 'test_vampir_native_enums.py')


def widget_schema():
    nested = {9, 17, 19, 21, 26}
    fields = [dict(name=name, gen_flags=flags) for i, (name, flags) in enumerate(zip(
        properties.WIDGET_FIELDS, properties.WIDGET_FLAGS)) if i not in nested]
    return dict(widget=dict(serialized_properties=fields), widget_transform=dict(properties=[dict(name=n)
        for n in ('Translation', 'Scale', 'Shear', 'Angle')]), scale_enums=dict(
        EStretch=[dict(value=i) for i in range(9)], EStretchDirection=[dict(value=i) for i in range(3)]))


class InheritedWidgetFields(unittest.TestCase):
    def test_render_translation_is_not_mistaken_for_scale(self):
        raw = struct.pack('<HHddI', 24 | 256 | (1 << 9), 256 | (1 << 9), 1, -1, 0)
        value = sizes.decode(raw, properties.FIELDS, widget_schema())
        transform = value['inherited_properties']['RenderTransform']['explicit_properties']
        self.assertEqual(transform, dict(Translation=[1, -1]))
        self.assertNotIn('Scale', transform)

    def test_visibility_and_opacity_follow_filtered_native_order(self):
        raw = struct.pack('<HHBfI', 34 | (1 << 9), 1 | 256 | (1 << 9), 2, .4, 0)
        value = sizes.decode(raw, properties.FIELDS, widget_schema())['inherited_properties']
        self.assertEqual(value['Visibility'], 2)
        self.assertAlmostEqual(value['RenderOpacity'], .4)

    def test_absent_transform_members_do_not_default_to_identity(self):
        raw = struct.pack('<HHI', 24 | 256 | (1 << 9), 256, 0)
        value = sizes.decode(raw, properties.FIELDS, widget_schema())
        self.assertEqual(value['inherited_properties']['RenderTransform']['explicit_properties'], {})

    def test_invalid_transform_or_opacity_is_rejected(self):
        for raw in (struct.pack('<HHddI', 24 | 256 | (1 << 9), 256 | (1 << 9), float('nan'), 0, 0),
                    struct.pack('<HfI', 36 | 256 | (1 << 9), 1.5, 0)):
            with self.assertRaises(ValueError):
                sizes.decode(raw, properties.FIELDS, widget_schema())

    def test_explicit_unparsed_text_or_binding_does_not_skip_bytes(self):
        for index in (20, 39):
            with self.assertRaises(ValueError):
                sizes.decode(struct.pack('<Hi', index | 256 | (1 << 9), 1), properties.FIELDS, widget_schema())


class ScaleContainerFields(unittest.TestCase):
    def decode(self, raw):
        return scales.decode(raw, ['Stretch', 'StretchDirection', 'UserSpecifiedScale', 'IgnoreInheritedScale'], widget_schema())

    def test_stretch_is_read_without_inventing_user_scale(self):
        value = self.decode(bytes.fromhex('000203050301000000110100003c01000000000000'))
        self.assertEqual(value['explicit_properties'], dict(Stretch=3))
        self.assertEqual(value['slots'], [273])
        self.assertEqual(value['incoming_slot'], 316)
        self.assertNotIn('UserSpecifiedScale', value['explicit_properties'])

    def test_native_bool_and_user_scale_are_independent(self):
        raw = struct.pack('<HfBI', 2 | 256 | (2 << 9), 1.5, 1, 0)
        value = self.decode(raw)['explicit_properties']
        self.assertEqual(value, dict(UserSpecifiedScale=1.5, IgnoreInheritedScale=True))

    def test_invalid_stretch_bool_scale_and_suffix_are_rejected(self):
        for raw in (struct.pack('<HBI', 256 | (1 << 9), 99, 0),
                    struct.pack('<HBI', 3 | 256 | (1 << 9), 2, 0),
                    struct.pack('<HfI', 2 | 256 | (1 << 9), -1, 0),
                    struct.pack('<HI', 256, 0) + b'\x01'):
            with self.assertRaises(ValueError):
                self.decode(raw)


class NativePropertyArray(unittest.TestCase):
    def fixture(self):
        data = pe_fixture.fixture()
        for offset, name in [(0x240, b'HeightOverride\0'), (0x270, b'WidthOverride\0')]:
            data[offset:offset + 32] = b'\0' * 32
            data[offset:offset + len(name)] = name
        data[0x300:0x380] = b'\0' * 128
        struct.pack_into('<Q', data, 0x300, 0x140001070)
        struct.pack_into('<I', data, 0x300 + 24, 10)
        struct.pack_into('<Q', data, 0x350, 0x140001040)
        struct.pack_into('<I', data, 0x350 + 24, 10)
        struct.pack_into('<QQ', data, 0x400, 0x140001100, 0x140001150)
        return data

    def extract(self, data):
        with patch.object(properties, 'FIELDS', ['WidthOverride', 'HeightOverride']):
            return properties.extract(data)

    def test_array_order_is_independent_of_string_order(self):
        result = self.extract(self.fixture())
        self.assertEqual(result['array_offset'], 0x400)
        self.assertEqual([p['name_offset'] for p in result['properties']], [0x270, 0x240])

    def test_wrong_property_type_or_pointer_rejected(self):
        for position, value in ((0x300 + 24, 12), (0x408, 0x777777)):
            data = self.fixture()
            struct.pack_into('<I' if position != 0x408 else '<Q', data, position, value)
            with self.assertRaises(ValueError):
                self.extract(data)

    def test_ambiguous_native_arrays_are_not_selected(self):
        data = self.fixture()
        data[0x420:0x430] = data[0x400:0x410]
        with self.assertRaises(ValueError):
            self.extract(data)


class ExplicitContainerSizes(unittest.TestCase):
    def decode(self, data):
        return sizes.decode(data, properties.FIELDS)

    def test_native_order_links_height_and_its_enable_flag(self):
        raw = bytes.fromhex('0102070206050000f0420101000000310000000f00000000000000')
        value = self.decode(raw)
        self.assertEqual(value['explicit_properties'], dict(HeightOverride=120, bOverride_HeightOverride=True))
        self.assertEqual(value['slots'], [49])
        self.assertEqual(value['incoming_slot'], 15)

    def test_value_without_enable_flag_remains_unknown(self):
        raw = struct.pack('<HfI', 256 | (1 << 9), 600, 0)
        value = self.decode(raw)['explicit_properties']
        self.assertEqual(value['WidthOverride'], 600)
        self.assertNotIn('bOverride_WidthOverride', value)

    def test_serialized_zero_override_is_explicit_false(self):
        raw = struct.pack('<HBI', 8 | 128 | 256 | (1 << 9), 1, 0)
        self.assertIs(self.decode(raw)['explicit_properties']['bOverride_WidthOverride'], False)

    def test_invalid_bool_and_nonfinite_float_rejected(self):
        for data in (struct.pack('<HBI', 8 | 256 | (1 << 9), 2, 0),
                     struct.pack('<HfI', 256 | (1 << 9), float('nan'), 0)):
            with self.assertRaises(ValueError):
                self.decode(data)

    def test_unresolved_inheritance_and_trailing_bytes_rejected(self):
        for data in (struct.pack('<H', 24 | 256 | (1 << 9)),
                     struct.pack('<HI', 256, 0) + b'\x01'):
            with self.assertRaises(ValueError):
                self.decode(data)

    def test_more_than_one_child_is_not_size_box(self):
        with self.assertRaises(ValueError):
            self.decode(struct.pack('<Hi', 16 | 256 | (1 << 9), 2))
