"""Explicit current Viper appearance projection retains resource unknowns."""
import copy
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent / 'resource-tools/vampir'


class CurrentViperAppearanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = spec_from_file_location('viper_appearance_current', HERE / 'build-viper-appearance-current.py')
        cls.tool = module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.result = cls.tool.verify()
        cls.report = json.loads(Path(cls.result['report']).read_bytes())

    def test_unchanged_projection_needs_no_native_or_resource_replay(self):
        with patch.object(self.tool, 'build', side_effect=AssertionError('Unexpected resource replay')):
            self.assertEqual(self.tool.verify(), dict(self.result, reused=True))
        self.assertFalse(self.report['native_execution'])
        self.assertTrue(self.report['native_proofs_reused'])
        self.assertFalse(self.report['runtime_admitted'])

    def test_preserves_raw_unknowns_and_serialized_values(self):
        female = self.report['appearances']['F']
        male = self.report['appearances']['M']
        self.assertIsNone(female['decoded']['values']['HairColorIndex'])
        self.assertEqual(female['candidate']['values']['HairColorIndex'], 0)
        self.assertEqual(female['candidate']['values']['SkinColorIndex'], 2)
        self.assertEqual(female['candidate']['values']['VoiceType'], 1)
        self.assertEqual(male['candidate']['values']['SkinColorIndex'], 0)
        self.assertEqual(male['candidate']['values']['VoiceType'], 0)
        self.assertTrue(all(female['candidate']['values'][name] == 0.5
                            for name in ('Height', 'Cheat', 'Shape', 'Waist', 'Pelvis', 'Thigh', 'Head')))
        for row in (female, male):
            for name, value in row['decoded']['values'].items():
                if value is not None:
                    self.assertEqual(row['candidate']['values'][name], value)
                    self.assertEqual(row['candidate']['origins'][name], row['decoded']['origins'][name])

    def test_rejects_changed_defaults_and_loaded_asset_claim(self):
        changed = copy.deepcopy(self.report)
        changed['defaults']['HairIndex'] = 3
        with self.assertRaisesRegex(ValueError, 'scope differs'):
            self.tool.validate(changed, self.report['definition'])
        changed = copy.deepcopy(self.report)
        changed['verified_loaded_asset'] = True
        with self.assertRaisesRegex(ValueError, 'scope differs'):
            self.tool.validate(changed, self.report['definition'])

    def test_corrupt_input_rejected_before_resource_processing(self):
        with patch.object(self.tool, 'digest', return_value='0' * 64), patch.object(self.tool, 'build') as build:
            with self.assertRaisesRegex(ValueError, 'input changed'):
                self.tool.verify()
            build.assert_not_called()


if __name__ == '__main__':
    unittest.main()
