"""Early current LoginResult handler paths, using declared service fixtures."""
import unittest
from test_vampir_update_contracts import load


class LoginHandlerEarly11320Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load('verify-login-handler-early-11320')
        cls.result = cls.tool.verify()

    def test_all_four_codes_and_optional_branches(self):
        cases = self.result['cases']
        self.assertEqual(len(cases), 14)
        self.assertEqual({c['code'] for c in cases}, {54, 9818, 9819, 90021})
        for code in (9818, 9819, 90021):
            self.assertEqual({c['optional_present'] for c in cases if c['code'] == code}, {False, True})
        self.assertTrue(all(c['abi'] and c['guards'] for c in cases))

    def test_branch_actions_and_scope_are_explicit(self):
        for case in self.result['cases']:
            actions = [e['action'] for e in case['events']]
            if case['code'] == 54:
                self.assertIn('popup54', actions)
                self.assertNotIn('error_finish', actions)
            elif case['code'] in (9818, 9819):
                self.assertEqual('error_9818' in actions, case['optional_present'])
                self.assertEqual(actions[-1], 'error_finish')
            else:
                self.assertEqual('error_90021' in actions, case['optional_present'])
                self.assertEqual(actions[-1], 'error_finish')
        self.assertFalse(self.result['gate_executed'])
        self.assertFalse(self.result['successful_login_executed'])
        self.assertFalse(self.result['network_used'])
        self.assertFalse(self.result['runtime_activated'])


if __name__ == '__main__':
    unittest.main()
