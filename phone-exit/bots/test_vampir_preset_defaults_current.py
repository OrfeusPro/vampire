"""Current constructor facts; complete loaded preset remains outside this check."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent / 'resource-tools/vampir'


class CurrentPresetDefaultsTests(unittest.TestCase):
    def test_current_constructor_preserves_omitted_integers_for_every_poison_and_service_branch(self):
        spec = importlib.util.spec_from_file_location('current_preset_default_fixture', HERE / 'verify-preset-defaults-current.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        result = tool.verify()
        report = json.loads(Path(result['report']).read_bytes())
        self.assertEqual(result['cases'], 25)
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['complete_loaded_preset_verified'])
        self.assertFalse(report['runtime_admitted'])
        self.assertEqual(len(report['descriptors']), 17)
        for case in report['cases']:
            self.assertFalse(case['integer_defaults_written'])
            self.assertEqual(case['floats'], [0.5] * 7)
            self.assertEqual(case['voice'], 0)


if __name__ == '__main__':
    unittest.main()
