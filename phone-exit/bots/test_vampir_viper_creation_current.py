"""Explicit current Viper factory scope, field provenance and cache integrity."""
import copy
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent / 'resource-tools/vampir'


class CurrentViperCreationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = spec_from_file_location('viper_creation_current', HERE / 'build-viper-creation-current.py')
        cls.tool = module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.result = cls.tool.verify()
        cls.report = json.loads(Path(cls.result['report']).read_bytes())

    def test_frozen_template_reused_without_projection(self):
        with patch.object(self.tool, 'build', side_effect=AssertionError('Unexpected factory rebuild')):
            repeated = self.tool.verify()
        self.assertEqual(repeated, dict(self.result, reused=True))
        self.assertEqual(self.report['selection'], dict(resource='DarkMage', row_id=1, class_type=1,
            gender_byte=1, preset_id=1, asset_suffix='F'))
        self.assertEqual(self.report['payload_template']['appearance'], [1, 1, 0, 1, 2, 1, 1, 0, 0, 1])
        self.assertEqual(json.loads(self.report['payload_template']['appearance_text']),
                         {**{str(index): 0.5 for index in range(1, 8)}, 'VoiceType': 1})
        self.assertNotIn('name', self.report['payload_template'])
        self.assertEqual(len(self.report['parents']), 6)

    def test_model_unknowns_retained_and_admission_claim_rejected(self):
        model = self.report['appearance_candidate']
        self.assertIsNone(model['decoded']['values']['Cheat'])
        self.assertEqual(model['candidate']['origins']['Cheat'], 'explicit_choice_from_current_cold_cdo_model')
        self.assertEqual(model['candidate']['values']['Cheat'], 0.5)
        self.assertFalse(model['candidate']['verified_loaded_asset'])
        for key in ('runtime_admitted', 'verified_loaded_asset'):
            changed = copy.deepcopy(self.report)
            changed[key] = True
            with self.assertRaisesRegex(ValueError, 'scope differs'):
                self.tool.validate(changed, self.report['definition'])

    def test_changed_input_rejected_before_parent_verification(self):
        with patch.object(self.tool, 'digest', return_value='0' * 64), patch.object(self.tool, 'parent_proofs') as parents:
            with self.assertRaisesRegex(ValueError, 'retained input changed'):
                self.tool.verify()
            parents.assert_not_called()

    def test_nonfinite_and_wire_byte_overflow_are_rejected(self):
        model = copy.deepcopy(self.report['appearance_candidate'])
        model['candidate']['values']['Cheat'] = float('nan')
        with self.assertRaisesRegex(ValueError, 'not finite'):
            self.tool.payload_template(self.report['selection'], model)
        model['candidate']['values']['Cheat'] = 0.5
        model['candidate']['values']['HairColorIndex'] = 256
        with self.assertRaisesRegex(ValueError, 'wire byte'):
            self.tool.payload_template(self.report['selection'], model)


if __name__ == '__main__':
    unittest.main()
