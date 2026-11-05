"""Source-bound reader/handler/gate composition for the current probe profile."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'
CONTEXT = HERE / 'knowledge/native-contexts/version-result-flow-11322.json'


class VersionResultFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('version_result_flow', HERE / 'verify-version-result-flow.py')
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.context = json.loads(CONTEXT.read_bytes())

    def test_native_reader_handler_gate_and_login_handoff(self):
        checks = json.loads((HERE / 'knowledge/research-checks.json').read_bytes())['checks']
        check = next(row for row in checks if row['id'] == 'native-version-result-handler-context')
        selected = [sha for sha, variant in check['source_variants'].items()
                    if variant['test_pattern'] == Path(__file__).name]
        self.assertEqual(selected, [self.context['source_sha256']])
        report = self.tool.verify(self.context, Path('F:/PhoneExit Resources/Vampir'))
        self.assertEqual(len(report['cases']), 16)
        self.assertEqual({(row['code'], row['flag']) for row in report['cases']},
                         {(code, flag) for code in self.tool.CODES for flag in (0, 1)})
        for row in report['cases']:
            self.assertEqual('login_prepare' in row['events'], row['code'] == 0 or (row['code'] == 0x1197 and row['flag'] == 0))
            self.assertEqual(row['consumed'], 17)
        self.assertTrue(report['native_input'] and report['native_handler'] and report['native_gate'])
        self.assertFalse(report['runtime_admitted'])

    def test_dependency_sha_and_scope_cannot_be_changed(self):
        context = copy.deepcopy(self.context)
        context['gate']['check']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'pointer SHA'):
            self.tool.dependency(Path('F:/PhoneExit Resources/Vampir'), context, 'gate', 'bounded_native_result_gate')
        with self.assertRaisesRegex(ValueError, 'source or scope'):
            self.tool.dependency(Path('F:/PhoneExit Resources/Vampir'), self.context, 'gate', 'whole_session')

    def test_source_change_stops_before_native_execution(self):
        context = copy.deepcopy(self.context)
        context['source_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'source or scope'):
            self.tool.verify(context, Path('F:/PhoneExit Resources/Vampir'))

    def test_unknown_recipe_is_rejected_before_reading_dependencies(self):
        with patch.object(self.tool, 'dependency') as called:
            with self.assertRaisesRegex(ValueError, 'recipe'):
                self.tool.verify({'schema': 1, 'recipe': 'other'}, Path('unused'))
            called.assert_not_called()
