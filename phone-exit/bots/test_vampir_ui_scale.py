import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('vampir_ui_scale_test', Path(__file__).parent / 'resource-tools/vampir/build-ui-scale-reference.py')
scale = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scale)


class SourceScaleProfiles(unittest.TestCase):
    def rows(self):
        return [dict(Key='DisplayUIScale' + profile + '.' + level, ValueType='float', Value=str(.6 + index * .1))
                for profile in scale.PROFILES for index, level in enumerate(scale.LEVELS)]

    def test_profiles_preserve_their_own_source_values_and_records(self):
        rows = self.rows()
        rows[-5]['Value'] = '.7'
        result = scale.presets(rows)
        self.assertEqual(result['AOS']['VerySmall']['value'], .6)
        self.assertEqual(result['AOSTablet']['VerySmall']['value'], .7)
        self.assertEqual(result['PC']['VerySmall']['csv_record'], 2)

    def test_duplicate_or_missing_profile_not_silently_filled(self):
        for rows in (self.rows()[:-1], self.rows() + [self.rows()[0]]):
            with self.assertRaises(ValueError):
                scale.presets(rows)

    def test_nonfinite_nonpositive_or_wrong_type_rejected(self):
        for key, value in (('Value', 'nan'), ('Value', 'inf'), ('Value', '0'),
                           ('Value', '-1'), ('ValueType', 'int32')):
            rows = self.rows()
            rows[0][key] = value
            with self.assertRaises(ValueError):
                scale.presets(rows)

    def test_similar_unrelated_keys_are_not_included(self):
        rows = self.rows() + [dict(Key='OtherDisplayUIScalePC.VerySmall', ValueType='float', Value='99')]
        self.assertEqual(sum(map(len, scale.presets(rows).values())), 25)

    def test_numeric_native_enum_and_csv_id_can_be_joined(self):
        self.assertEqual(scale.one([dict(value=137, name='DisplayUIScale')], 'value', '137')['name'], 'DisplayUIScale')

    def test_missing_or_ambiguous_option_reference_is_rejected(self):
        for rows in ([], [dict(Id='32300'), dict(Id='32300')]):
            with self.assertRaises(ValueError):
                scale.one(rows, 'Id', '32300')
