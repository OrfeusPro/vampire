"""Current parameter proofs stay bounded, immutable and separate from game actions."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name):
    path = HERE / 'resource-tools/vampir' / (name + '.py')
    spec = importlib.util.spec_from_file_location('test_' + name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class QuestParametersCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load('verify-quest-parameters-current')
        cls.pointer = cls.tool.verify()
        cls.report = json.loads(Path(cls.pointer['report']).read_bytes())

    def test_native_scopes_do_not_grant_active_task_or_action_permission(self):
        report = self.report
        self.assertTrue(report['native_execution'])
        self.assertEqual(set(report['results']), {'binding', 'scalar'})
        for field in ('runtime_admitted', 'active_task_verified', 'dialogue_started',
                      'skip_behavior_verified', 'network_used', 'class_string_conversion_verified'):
            self.assertIs(report[field], False)
        scalar = report['results']['scalar']
        self.assertEqual(len(scalar['cases']), 436)
        self.assertEqual(scalar['metrics']['abi_checks'], 436)
        self.assertTrue(scalar['non_null_shared_control_executed'])

    def test_present_field_does_not_imply_successful_numeric_provider(self):
        rows = [row for row in self.report['results']['scalar']['cases']
                if row['case']['presence'] == 'present' and row['case']['alignment'] == 0
                and row['case']['key'] == 'classInfoId' and row['case']['control'] == 'none']
        failed = next(row for row in rows if row['case']['provider']['label'] == 'failed')
        partial = next(row for row in rows if row['case']['provider']['label'] == 'write-then-failed')
        self.assertTrue(failed['success'])
        self.assertEqual(failed['output'], 0)
        self.assertTrue(partial['success'])
        self.assertEqual(partial['output'], 7)
        self.assertIn('error_string', partial['events'])

    def test_warm_cache_does_not_execute_native_or_spawn_processes(self):
        original = self.tool.load
        modules = {name: original(name) for name in ('quest-param-binding-cases-v1', 'quest-param-scalar-cases-v1')}
        def selected(name):
            return modules[name] if name in modules else original(name)
        with patch.object(self.tool, 'load', side_effect=selected), \
                patch.object(modules['quest-param-binding-cases-v1'], 'execute', side_effect=AssertionError('binding replay')), \
                patch.object(modules['quest-param-scalar-cases-v1'], 'execute', side_effect=AssertionError('scalar replay')), \
                patch('subprocess.Popen', side_effect=AssertionError('process spawn')):
            self.assertEqual(self.tool.verify(), dict(self.pointer, reused=True))

    def test_incomplete_results_and_forged_gameplay_scope_are_rejected(self):
        definition = self.report['definition']
        for kind in ('binding', 'scalar'):
            forged = copy.deepcopy(self.report)
            forged['results'][kind]['cases'] = []
            with self.assertRaises(ValueError):
                self.tool.validate(forged, definition)
        for field in ('runtime_admitted', 'active_task_verified', 'class_string_conversion_verified'):
            with self.assertRaisesRegex(ValueError, 'scope differs'):
                self.tool.validate(dict(self.report, **{field: True}), definition)

    def test_cached_receipt_has_a_final_input_barrier(self):
        with patch.object(self.tool, 'barrier', side_effect=[None, ValueError('late input mutation')]) as checked:
            with self.assertRaisesRegex(ValueError, 'late input mutation'):
                self.tool.verify()
        self.assertEqual(checked.call_count, 2)


if __name__ == '__main__':
    unittest.main()
