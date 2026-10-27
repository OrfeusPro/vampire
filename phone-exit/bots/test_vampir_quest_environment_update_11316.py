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
            self.assertEqual(c['phase_after'], 3)
            self.assertEqual(c['phase_notifications'], 1)
            self.assertEqual(c['callback_al'], 1 if accepted else None)
            self.assertEqual(c['calls'].count('callback-process'), int(accepted))
        for c in phases:
            selected = c['phase'] in (2, 3, 4)
            self.assertEqual(c['result'], int(selected))
            self.assertEqual(c['calls'], ['format', 'phase:5'] if selected else [])
            self.assertEqual(c['phase_after'], 5 if selected else c['phase'])
            self.assertEqual(c['phase_notifications'], int(selected))
        lookups = {c['mode']:c for c in result['lookup_cases']}
        self.assertEqual(set(lookups), {'global', 'fallback', 'wrong-depth', 'wrong-parent',
            'fallback-missing', 'resolve-missing', 'owner-empty', 'explicit-owner', 'explicit-empty'})
        for mode, c in lookups.items():
            self.assertEqual(c['found'], mode not in
                ('fallback-missing', 'resolve-missing', 'owner-empty', 'explicit-empty'))
        self.assertEqual(lookups['global']['calls'], ['world', 'object-class', 'resolve'])
        self.assertEqual(lookups['fallback']['calls'], ['world', 'fallback', 'resolve'])
        self.assertEqual(lookups['wrong-parent']['calls'], ['world', 'object-class', 'fallback', 'resolve'])
        self.assertEqual(lookups['explicit-owner']['calls'], ['world'])
        self.assertEqual(len(result['phase_cases']), 16)
        self.assertEqual({(c['previous'], c['phase']) for c in result['phase_cases']},
            {(before, after) for before in (0, 7) for after in (0, 1, 2, 3, 5, 6, 7, 255)})
        for c in result['phase_cases']:
            self.assertEqual(c['phase_after'], c['phase'])
            self.assertEqual(c['notifications'], 1)
        self.assertEqual(len(result['callback_cases']), 24)
        self.assertEqual({(c['present'], c['can'], c['count'], c['external_flag']) for c in result['callback_cases']},
            {(present, can, count, flag) for present in (False, True) for can in (False, True)
                for count in (0, 1, 2) for flag in (0, 1)})
        for c in result['callback_cases']:
            accepted = not c['present'] or c['can']
            copied = accepted and c['count']<2 and not c['external_flag']
            self.assertEqual(c['result_al'], int(accepted))
            self.assertEqual(c['copied'], copied)
            self.assertEqual(c['process_calls'], int(copied and c['present']))
            self.assertEqual(c['phase_after'], 7)


if __name__ == '__main__':
    unittest.main()
