"""Actual completion writes phase6 before notification without changing world fields."""
import importlib.util
from pathlib import Path
import unittest


class CompletionTests(unittest.TestCase):
    def test_completion_transition_and_ordering(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-quest-environment-completion-11316.py'
        spec = importlib.util.spec_from_file_location('completion_replay', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        artifact, result = module.run()
        self.assertTrue(artifact.is_file())
        self.assertEqual(result['source_sha256'], module.SHA)
        self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_used'])
        self.assertFalse(result['action_admitted'])
        self.assertEqual(len(result['cases']), 28)
        for derived in (False, True):
            rows = [row for row in result['cases'] if row['derived'] == derived]
            self.assertEqual({row['before'] for row in rows}, {0, 2, 3, 4, 5, 6, 7})
            for row in rows:
                self.assertEqual(row['after'], 6)
                self.assertTrue(row['phase_gate_passed'])
                self.assertEqual(row['events'], ['phase-format', 'phase-notify', 'event-clear', 'ui-reset'])


if __name__ == '__main__':
    unittest.main()
