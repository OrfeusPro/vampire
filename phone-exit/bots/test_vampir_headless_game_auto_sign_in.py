"""Source-bound game AutoSignIn result branches, with external actions captured."""
import importlib.util
import json
from pathlib import Path
import unittest


class GameAutoSignInTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-game-auto-sign-in-result.py'
        spec=importlib.util.spec_from_file_location('auto_game_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/game-auto-sign-in-result-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_source_and_distinct_sdk_route(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),15)
        self.assertIn('FNnNetmarbleSDKAuth::AutoSignIn',self.report['diagnostic']['text'])
        self.assertEqual(len(self.report['verified_xrefs']),3)
        self.assertEqual({r['root'] for r in self.report['route_diagnostics']},{0x144521550,0x1444feac0})
        self.assertTrue(any('GetChannelManager(' in r['literal']['text'] for r in self.report['route_diagnostics']))
        self.assertTrue(any('FChannelManagerImpl::SignInSilently(' in r['literal']['text'] for r in self.report['route_diagnostics']))
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x1445215bf]['operands'],'rax, [rbx + 0x170]')
        self.assertEqual(rows[0x1456005cd]['direct_target'],0x1444fea30)
        self.assertEqual(self.report['leaves'][0]['instructions'][0]['operands'],'0x1455fbb80')

    def test_weak_owner_and_success_boundaries(self):
        for name in ('no-weak','expired','no-owner'):
            self.assertEqual(self.cases[name]['events'],[])
        for case in self.report['cases']:
            self.assertEqual(case['strong_after'],case['fixture']['strong'])
        events=self.cases['success']['events']
        self.assertEqual([e['action'] for e in events],['result_log_capture','manager_action_capture',
                         'manager_child_capture','game_instance_getter_fixture'])
        self.assertEqual(events[1]['target_pointer'],0x143b8bf10)

    def test_error_branches(self):
        for code in (40040011,30050012):
            for status in (429,502,200):
                events=self.cases[f'special-{code}-{status}']['events']
                self.assertEqual(len(events),1 if status==200 else 2)
                if status!=200:self.assertEqual(events[1]['action'],'manager_action_capture')
        for status in (1100,1202,1210):
            self.assertEqual(self.cases[f'fallback-status-{status}']['events'][-1]['action'],'fallback_capture')
        self.assertEqual(self.cases['fallback-status-200']['events'][-1]['action'],'error_action_capture')
        self.assertEqual(self.cases['ordinary-error']['events'][-1]['action'],'fallback_capture')


if __name__=='__main__':
    unittest.main()
