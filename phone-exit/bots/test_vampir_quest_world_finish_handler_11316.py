"""Native ID206 accepted/error/early paths must preserve scope and reference balance."""
import importlib.util
from pathlib import Path
import unittest


class FinishHandlerTests(unittest.TestCase):
    def test_whole_handler_gate_receiver_completion(self):
        p = Path(__file__).parent / 'resource-tools/vampir/replay-quest-environment-completion-11316.py'
        spec = importlib.util.spec_from_file_location('finish_handler', p)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        artifact, result = module.run(with_world_finish=True, with_handler=True)
        self.assertTrue(artifact.is_file())
        self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_used'])
        self.assertFalse(result['action_admitted'])
        rows = result['world_finish']['handler_cases']
        self.assertEqual(len(rows), 16)
        self.assertEqual(sum(row['accepted'] for row in rows), 3)
        for row in rows:
            self.assertEqual(row['refcount'], 2)
            if not row['key_present']:
                self.assertEqual(row['events'], [])
                self.assertEqual(row['phase'], 3)
            elif row['accepted']:
                self.assertEqual(row['phase'], 6)
                self.assertIn('post-effects', row['events'])
                self.assertEqual('error' in row['events'], row['code'] == 0x1197)
            else:
                self.assertEqual(row['phase'], 3)
                self.assertEqual(row['events'][-1], 'rejected')
                self.assertNotIn('phase-notify', row['events'])


if __name__ == '__main__':
    unittest.main()
