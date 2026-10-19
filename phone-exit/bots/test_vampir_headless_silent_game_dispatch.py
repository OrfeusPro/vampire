"""Silent result queue reaches native game callback without becoming auth proof."""
import importlib.util
import json
from pathlib import Path
import unittest


class SilentGameDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-silent-game-dispatch.py'
        spec=importlib.util.spec_from_file_location('silent_game_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/silent-game-dispatch-replay.json').read_text('utf-8'))

    def test_source_bound_silent_route(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),12)
        self.assertTrue(any('FAuthImpl::ExecSignInSilently(' in r['text'] for r in self.report['literals']))
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x1444e0361]['operands'],'rdx, [rsi + 0xa8]')
        self.assertEqual(rows[0x1444ce7f2]['direct_target'],0x1444e02e0)
        self.assertEqual(self.report['response_jump']['target'],0x1444cdb30)
        self.assertEqual(self.report['request_callback_instructions'][0]['rip_references'],[0x1444d8610])
        self.assertEqual(self.report['request_callback_instructions'][-1]['direct_target'],0x14451c3f0)

    def test_deferred_original_response_and_reference_counts(self):
        for case in self.report['cases']:
            with self.subTest(case['fixture']):
                f=case['fixture'];events=case['events'];actions=[e['action'] for e in events]
                self.assertTrue(case['original_delegate_cleared'])
                self.assertTrue(case['response_pair_preserved'])
                expected=5 if f['refcounted'] else 4
                self.assertEqual(case['response_strong_after_dispatch'],expected)
                self.assertEqual(case['response_strong_after_thunk'],expected)
                self.assertEqual(case['owner_strong_after'],f['strong'])
                if f['bound']:
                    self.assertEqual(actions.count('native_game_callback_entry'),1)
                    self.assertLess(actions.index('fixture_task_drain'),actions.index('native_game_callback_entry'))
                    self.assertEqual([e['al'] for e in events if e['action']=='native_silent_delegate_return'],[1])
                else:self.assertNotIn('native_game_callback_entry',actions)

    def test_lifetime_and_game_result_branches(self):
        for case in self.report['cases']:
            name=case['fixture']['name'];events=case['events'];actions=[e['action'] for e in events]
            if name in ('expired','no-owner','no-binding'):
                self.assertNotIn('result_log_capture',actions)
                self.assertNotIn('manager_action_capture',actions)
            elif name=='success':
                self.assertIn('game_instance_getter_fixture',actions)
                self.assertEqual(next(e for e in events if e['action']=='manager_action_capture')['target_pointer'],0x143b8bf10)
            elif name=='ordinary-error':self.assertIn('fallback_capture',actions)
            elif name=='special-429':
                self.assertEqual(next(e for e in events if e['action']=='manager_action_capture')['target_pointer'],0x144569170)


if __name__=='__main__':
    unittest.main()
