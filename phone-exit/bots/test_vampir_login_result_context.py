import json
from pathlib import Path
import sys
import unittest

from test_vampir_update_contracts import load, HERE

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.login_result import decode_login_result

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/login-result-11316.json'


class LoginResultContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_whole_current_reader_and_portable_decoder(self):
        report = load('verify-login-result-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 320)
        self.assertEqual(len(report['truncated']), 332)
        self.assertEqual(len(report['failures']), 25)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
        for case in report['cases']:
            self.assertTrue(case['guards'])
            body = bytes.fromhex(case['body_hex'])
            model = decode_login_result(body, max_payload_size=4096)
            self.assertEqual(case['consumed'], len(body))
            for key in ('strings', 'u32', 'u16', 'u64', 'flags'):
                self.assertEqual(list(getattr(model, key)), case['fields'][key])
        for case in report['truncated']:
            self.assertEqual(case['returned'], 0)
            with self.assertRaises(ValueError):
                decode_login_result(bytes.fromhex(case['body_hex']), max_payload_size=4096)
        for index, case in enumerate(report['failures']):
            self.assertEqual(len(case['operations']), index + 1)
            self.assertEqual(case['returned'], 0)
        self.assertEqual(report['trailing']['consumed'], 99)
        with self.assertRaisesRegex(ValueError, 'Trailing bytes'):
            decode_login_result(bytes.fromhex(report['trailing']['body_hex']), max_payload_size=4096)

    def test_corrupt_source_or_export_rejected(self):
        tool = load('verify-login-result-context')
        context = self.context()
        context['source_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'source path differs'):
            tool.verify(context, ROOT)
        context = self.context()
        context['exports']['run-3c0581002a58'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            tool.verify(context, ROOT)

    def test_changed_call_table_or_id_rejected(self):
        tool = load('verify-login-result-context')
        context = self.context()
        context['call_sites'][next(iter(context['call_sites']))]['target'] = '0x1457a3501'
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            tool.verify(context, ROOT)
        context = self.context()
        context['packet_table'] = '0x149926591'
        with self.assertRaisesRegex(ValueError, 'reader table link differs'):
            tool.verify(context, ROOT)
        context = self.context()
        context['id_getter'] = '0x141453c41'
        with self.assertRaisesRegex(ValueError, 'ID table link differs'):
            tool.verify(context, ROOT)


class CurrentLoginContextTests(unittest.TestCase):
    def test_11318_whole_registered_context(self):
        from test_vampir_login_batch_support import verify_current
        verify_current(self, 'login-result', 'verify-login-result-context')


if __name__ == '__main__':
    unittest.main()
