import json
from pathlib import Path
import sys
import unittest

from test_vampir_update_contracts import load, HERE

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.login_result import decode_login_result

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/login-result-input-11316.json'


class LoginResultInputContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_actual_numeric_archive_in_whole_result_reader(self):
        report = load('verify-login-result-context').verify(self.context(), ROOT)
        self.assertTrue(report['native_input_used'])
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
        self.assertEqual((len(report['cases']), len(report['truncated']), len(report['failures'])), (320, 332, 25))
        for case in report['cases']:
            self.assertEqual(case['input_entries'], dict(u32=3, u16=2, time=6, u64=2, bool=5))
            self.assertEqual(case['last_count'], 1)
            self.assertTrue(case['guards'])
            model = decode_login_result(bytes.fromhex(case['body_hex']), max_payload_size=4096)
            for key in ('strings', 'u32', 'u16', 'u64', 'flags'):
                self.assertEqual(list(getattr(model, key)), case['fields'][key])
        self.assertEqual({case['fields']['flags'][0] for case in report['cases']}, {0, 1})
        for case in report['truncated']:
            self.assertEqual(case['returned'], 0)
            self.assertLessEqual(case['consumed'], len(bytes.fromhex(case['body_hex'])))
        for index, case in enumerate(report['failures']):
            self.assertEqual((case['returned'], len(case['operations'])), (0, index + 1))
        self.assertEqual((report['trailing']['returned'], report['trailing']['consumed']), (1, 99))

    def test_changed_input_source_or_export_rejected(self):
        tool = load('verify-login-result-context')
        context = self.context()
        context['native_input']['source_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'input source differs'):
            tool.verify(context, ROOT)
        context = self.context()
        context['native_input']['exports']['run-6c5bd9da86eb'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            tool.verify(context, ROOT)

    def test_changed_input_call_or_table_rejected(self):
        tool = load('verify-login-result-context')
        context = self.context()
        context['native_input']['call_sites'][next(iter(context['native_input']['call_sites']))]['target'] = '0x144aace11'
        with self.assertRaisesRegex(ValueError, 'Input archive call sites differ'):
            tool.verify(context, ROOT)
        context = self.context()
        context['native_input']['table_bytes'] = '00' + context['native_input']['table_bytes'][2:]
        with self.assertRaisesRegex(ValueError, 'Input archive table differs'):
            tool.verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
