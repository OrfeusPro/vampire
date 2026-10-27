import json
from pathlib import Path
import sys
import unittest

from test_vampir_update_contracts import load, HERE

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.login_result import decode_login_result

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/login-result-string-11316.json'


class LoginResultStringContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_native_strings_utf8_cleanup_and_boundaries(self):
        report = load('verify-login-result-context').verify(self.context(), ROOT)
        self.assertTrue(report['native_string_used'])
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
        self.assertEqual((len(report['cases']), len(report['truncated']), len(report['failures'])), (160, 332, 25))
        self.assertEqual(len(report['boundaries']), 4)
        for case in report['cases'] + report['boundaries']:
            self.assertTrue(case['guards'])
            self.assertEqual(case['input_entries']['string'], 7)
            model = decode_login_result(bytes.fromhex(case['body_hex']), max_payload_size=4096)
            for key in ('strings', 'u32', 'u16', 'u64', 'flags'):
                self.assertEqual(list(getattr(model, key)), case['fields'][key])
        self.assertEqual([len(c['fields']['strings'][0]) for c in report['boundaries']], [15, 16, 127, 128])
        self.assertEqual(len(report['special']), 6)
        for case in report['special']:
            self.assertEqual(case['returned'], 1)
            with self.assertRaises(ValueError):
                decode_login_result(bytes.fromhex(case['body_hex']), max_payload_size=4096)
        self.assertEqual(report['special'][4]['fields']['strings'][0], 'a')
        self.assertTrue(all(c['returned'] == 0 for c in report['truncated'] + report['failures']))

    def test_explicit_function_budget_required(self):
        context = self.context()
        context.pop('function_budget')
        with self.assertRaisesRegex(ValueError, 'function/export budget exceeded'):
            load('verify-login-result-context').verify(context, ROOT)

    def test_changed_utf8_callee_or_export_rejected(self):
        tool = load('verify-login-result-context')
        context = self.context()
        context['native_input']['exports']['run-2fe73e379c6f'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            tool.verify(context, ROOT)
        context = self.context()
        site = next(site for site, spec in context['native_input']['call_sites'].items() if spec['target'] == '0x14143bd30')
        context['native_input']['call_sites'][site]['target'] = '0x14143bd31'
        with self.assertRaisesRegex(ValueError, 'Input archive call sites differ'):
            tool.verify(context, ROOT)


class CurrentLoginContextTests(unittest.TestCase):
    def test_11318_whole_registered_context(self):
        from test_vampir_login_batch_support import verify_current
        verify_current(self, 'login-result-string', 'verify-login-result-context')


if __name__ == '__main__':
    unittest.main()
