"""Native immediate/deferred preset completion with explicit queue boundaries."""
import importlib.util
from pathlib import Path
import unittest


class PresetCompletionTests(unittest.TestCase):
    def test_immediate_and_deferred_completion(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-preset-completion.py'
        spec = importlib.util.spec_from_file_location('preset_completion_test', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        _, report = module.run()
        cases = report['postconstruct_cases']
        self.assertEqual(len(cases), 24)
        self.assertEqual({c['route'] for c in cases}, {'immediate_dependency_false',
            'immediate_setting', 'immediate_class_ready', 'deferred'})
        self.assertEqual(sum(c['queued_initializer_marked'] for c in cases), 6)
        for case in cases:
            self.assertTrue(case['context_popped'])
            self.assertTrue(case['all_other_object_bytes_unchanged'])
            deferred = case['route'] == 'deferred'
            self.assertEqual(case['flags_after'], 0x231 if deferred else 0x31)
            self.assertEqual(case['initializer_object_cleared'], not deferred)
            self.assertEqual('0x1416314d0' in case['fixture_calls'], deferred)


if __name__ == '__main__': unittest.main()
