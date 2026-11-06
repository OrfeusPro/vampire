"""Small fixture checks for preset selection; no native scenarios, game or network."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch


HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('preset_selection_fixtures',
    HERE / 'resource-tools/vampir/extract-release-creation-presets.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def tables():
    return [dict(package=path, rows=[dict(id=1, class_type=1,
        asset=tool.PREFIX + 'DataAsset/Customize/DA_PresetDarkMage1_' + path[-1] +
        '.DA_PresetDarkMage1_' + path[-1]), dict(id=3, class_type=3,
        asset=tool.PREFIX + 'DataAsset/Customize/UnrelatedName.UnrelatedName')]) for path in tool.TABLES]


class PresetResourceSelectionTests(unittest.TestCase):
    def test_class_gender_and_explicit_id_select_table_links_without_filename_inference(self):
        source = tables()
        both = tool.select_presets(source, class_type=1)
        self.assertEqual([link['preset_id'] for link in both], [1, 1])
        self.assertEqual([link['package'].rsplit('/', 1)[-1] for link in both],
                         ['DA_PresetDarkMage1_F', 'DA_PresetDarkMage1_M'])
        self.assertEqual(tool.select_presets(source, class_type=1, preset_id=1, gender='M'), both[1:])
        self.assertEqual(tool.select_presets(source, class_type=3)[0]['package'].rsplit('/', 1)[-1],
                         'UnrelatedName')

    def test_ambiguous_class_needs_explicit_id_and_missing_selection_is_not_fallback(self):
        source = tables()
        duplicate = copy.deepcopy(source[0]['rows'][0]); duplicate['id'] = 2
        source[0]['rows'].append(duplicate)
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            tool.select_presets(source, class_type=1)
        self.assertEqual(tool.select_presets(source, class_type=1, preset_id=2, gender='F')[0]['preset_id'], 2)
        with self.assertRaisesRegex(ValueError, 'missing'):
            tool.select_presets(source, class_type=1, preset_id=2)
        for source in (tables()[:1], tables() + tables()[:1]):
            with self.assertRaisesRegex(ValueError, 'missing or duplicated'):
                tool.select_presets(source, class_type=1)

    def test_bad_options_and_foreign_reference_fail_before_extraction(self):
        for options in ({'class_type': True}, {'class_type': -1}, {'class_type': 256},
                        {'preset_id': True}, {'preset_id': -1}, {'gender': 'Female'},
                        {'resource_only': 1}):
            with self.subTest(options=options), patch.object(tool, 'load', side_effect=AssertionError('IO')):
                with self.assertRaises(ValueError):
                    tool.extract(None, None, None, **options)
        source = tables()
        source[0]['rows'][0]['asset'] = '/Untrusted/DA_Test.DA_Test'
        with self.assertRaisesRegex(ValueError, 'path'):
            tool.select_presets(source, class_type=1)

    def test_resource_only_omitted_fields_remain_unknown_while_serialized_zero_is_zero(self):
        empty = struct.pack('<HI', 0x100, 0)
        observed = tool.asset(empty, use_constructor_defaults=False)
        self.assertEqual(set(observed['unresolved']), set(tool.ASSET_FIELDS))
        self.assertTrue(all(value is None for value in observed['values'].values()))
        self.assertEqual(tool.asset(empty)['values']['VoiceType'], 0)
        # One property has an explicit serialized zero mask.
        zero = struct.pack('<HBI', (1 << 9) | 0x180, 1, 0)
        observed = tool.asset(zero, use_constructor_defaults=False)
        self.assertEqual(observed['values']['HairIndex'], 0)
        self.assertEqual(observed['origins']['HairIndex'], 'serialized_zero')
        self.assertIsNone(observed['values']['VoiceType'])

    def test_complete_asset_and_every_prefix_preserve_parser_bounds(self):
        body = struct.pack('<H9i7fBI', (17 << 9) | 0x100,
                           *range(9), *([0.25] * 7), 2, 0)
        decoded = tool.asset(body, use_constructor_defaults=False)
        self.assertEqual(decoded['unresolved'], [])
        self.assertEqual(decoded['values']['VoiceType'], 2)
        self.assertEqual(decoded['values']['HairColorIndex'], 2)
        for size in range(len(body)):
            with self.subTest(size=size), self.assertRaises((ValueError, struct.error)):
                tool.asset(body[:size], use_constructor_defaults=False)
        with self.assertRaises(ValueError):
            tool.asset(body + b'\0', use_constructor_defaults=False)


if __name__ == '__main__':
    unittest.main()
