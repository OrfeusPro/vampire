import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/login-result-buffer-11316.json'


class LoginResultBufferContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_native_buffer_construction_and_whole_reader(self):
        report = load('verify-login-result-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['construction_cases']), 72)
        self.assertEqual({c['function'] for c in report['construction_cases']}, {'constructor', 'buffer_constructor'})
        self.assertTrue(all(c['guards'] for c in report['construction_cases']))
        self.assertEqual((len(report['cases']), len(report['truncated']), len(report['failures'])), (160, 332, 25))
        self.assertTrue(all(c['returned'] == 0 for c in report['truncated'] + report['failures']))
        self.assertTrue(report['native_string_used'])
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])

    def test_scope_and_budget_cannot_expand(self):
        for budget, scope in ((20, None), (20, 'other'), (21, 'login-result-buffer'), (32, 'login-result-buffer')):
            context = self.context()
            context.update(function_budget=budget, budget_scope=scope)
            with self.assertRaisesRegex(ValueError, 'function/export budget exceeded'):
                load('verify-login-result-context').verify(context, ROOT)

    def test_changed_constructor_link_or_table_rejected(self):
        context = self.context()
        context['native_input']['call_sites']['0x144aacb56']['target'] = '0x144aac190'
        with self.assertRaisesRegex(ValueError, 'Input archive call sites differ'):
            load('verify-login-result-context').verify(context, ROOT)
        context = self.context()
        context['native_input']['buffer_construction']['base_table'] = '0x149670880'
        with self.assertRaisesRegex(ValueError, 'Input buffer construction scope differs'):
            load('verify-login-result-context').verify(context, ROOT)


class CurrentLoginContextTests(unittest.TestCase):
    def test_11318_whole_registered_context(self):
        from test_vampir_login_batch_support import verify_current
        verify_current(self, 'login-result-buffer', 'verify-login-result-context')


if __name__ == '__main__':
    unittest.main()
