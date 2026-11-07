"""Check the position correction scope and reuse through the normal update gate."""
import copy
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


class OwnPositionCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = spec_from_file_location('verify_own_position_current', HERE / 'verify-own-position-current.py')
        cls.tool = module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.pointer = cls.tool.verify()
        cls.report = json.loads(Path(cls.pointer['report']).read_bytes())
        cls.context, cls.selected = cls.tool.definition(
            cls.tool.load('knowledge-index').api(), cls.tool.ROOT, cls.tool.CONTEXT)

    def test_changed_native_source_cannot_reuse_proof(self):
        for section, name in (('roles', 'corrector'), ('source_roles', 'spawn'),
                              ('constants', 'capsule_bias')):
            context = copy.deepcopy(self.context)
            context[section][name] = '0x1456a6d10'
            with self.subTest(section=section, name=name), self.assertRaises(ValueError):
                self.tool.validate(self.report, self.selected, context)

    def test_changed_case_cannot_reuse_proof(self):
        report = copy.deepcopy(self.report)
        report['result']['cases'] = report['result']['cases'][1:]
        with self.assertRaises(ValueError):
            self.tool.validate(report, self.selected, self.context)

    def test_live_position_claim_requires_separate_proof(self):
        for field in self.tool.FALSE_FIELDS:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.tool.validate(dict(self.report, **{field: True}), self.selected, self.context)

    def test_cached_proof_reuses_validated_inputs_without_execution(self):
        sys.path.insert(0, str(HERE.parents[2] / '.tools/vampir-analysis'))
        from unicorn import Uc
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected child process')), \
                patch.object(Uc, 'emu_start', side_effect=AssertionError('unexpected native replay')):
            result = self.tool.verify()
        self.assertTrue(result['reused'])
        self.assertEqual(result['sha256'], self.pointer['sha256'])


if __name__ == '__main__':
    unittest.main()
