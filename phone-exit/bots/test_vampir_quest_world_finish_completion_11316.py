"""ID206 native receiver must apply world fields before actual completion phase6."""
import importlib.util
from pathlib import Path
import unittest


class FinishCompletionTests(unittest.TestCase):
    def test_receiver_state_refcounts_and_completion(self):
        p = Path(__file__).parent / 'resource-tools/vampir/replay-quest-environment-completion-11316.py'
        spec = importlib.util.spec_from_file_location('finish_completion', p)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        artifact, result = module.run(with_world_finish=True)
        self.assertTrue(artifact.is_file())
        self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_used'])
        self.assertFalse(result['action_admitted'])
        self.assertEqual(len(result['cases']), 28)
        finish = result['world_finish']
        self.assertEqual(finish['static_binding']['packet_id'], 206)
        self.assertEqual(finish['static_binding']['handler'], '0x1467ca450')
        self.assertEqual(len(finish['cases']), 24)
        for row in finish['cases']:
            self.assertEqual((row['after'], row['refcount']), (6, 2))
            self.assertEqual(row['computed_flag79'], row['old_quest'] == row['new_quest'] == 0)
            self.assertLess(row['events'].index('actor-create-missing'), row['events'].index('phase-notify'))


if __name__ == '__main__':
    unittest.main()
