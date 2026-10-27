"""Native environment field commit controls the actual quest readiness predicate."""
import importlib.util
from pathlib import Path
import unittest


class QuestEnvironmentUpdateTests(unittest.TestCase):
    def test_commit_retry_refusal_and_phase_paths(self):
        path = Path(__file__).parent/'resource-tools/vampir/replay-quest-environment-update-11316.py'
        spec = importlib.util.spec_from_file_location('quest_environment_update', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target, result = module.run()
        self.assertTrue(target.is_file())
        self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_used']); self.assertFalse(result['action_admitted'])
        self.assertEqual(result['legacy_direct_flow_checked'], ['0x14561bca0'])
        commits = [c for c in result['cases'] if c['path'] != 'phase']
        phases = [c for c in result['cases'] if c['path'] == 'phase']
        self.assertEqual(len(commits), 36); self.assertEqual(len(phases), 12)
        for c in commits:
            accepted = c['guard'] == 'allow'
            self.assertEqual(c['actual'], c['requested'] if accepted else c['old'])
            self.assertEqual(c['pending'], 0 if accepted else c['requested'])
            self.assertEqual(c['flag_c1'], int(c['path']=='retry' or not accepted))
            self.assertEqual(c['ready_before'], c['old']==c['requested'])
            self.assertEqual(c['ready_after'], accepted or c['old']==c['requested'])
            self.assertEqual(c['calls'].count('callback'), int(accepted))
        for c in phases:
            selected = c['phase'] in (2, 3, 4)
            self.assertEqual(c['result'], int(selected))
            self.assertEqual(c['calls'], ['format', 'phase:5'] if selected else [])


if __name__ == '__main__':
    unittest.main()
