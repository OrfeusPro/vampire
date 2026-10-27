import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')


class LoginContinuationContextTests(unittest.TestCase):
    def context(self):
        return json.loads((HERE / 'knowledge/native-contexts/login-continuation-11316.json').read_text('utf-8'))

    def test_actual_constructor_getter_and_final_slot_reset(self):
        report = load('verify-login-continuation-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 8)
        self.assertFalse(report['network_used'] or report['profile_activated'])
        for c in report['cases']:
            self.assertEqual(c['ctor_vptrs'], [0x149cb7b18, 0x149cb7b48])
            for at in ('0xf0', '0x140', '0x190', '0x210', '0x260', '0x2b0', '0x300'):
                self.assertEqual(c['values'][at], min(c['level'], 1))
            for at in ('0x244', '0x294', '0x2e4'):
                self.assertEqual(c['values'][at], 128)
            for at in ('0x248', '0x298', '0x2e8'):
                self.assertEqual(c['values'][at], 0xffffffff)
            for at in ('0x1a0', '0x1b0', '0x220', '0x240', '0x24c', '0x270', '0x290', '0x29c',
                       '0x2c0', '0x2e0', '0x2ec', '0x338', '0x33c'):
                self.assertEqual(c['values'][at], 0)
            self.assertEqual((c['field308'], c['flag']), (0, 0))
            shrink = [e for e in c['events'] if e['address'] == '0x141433e10']
            self.assertEqual(len(shrink), 3 if c['capacity'] > 128 else 0)
            self.assertTrue(c['guards'])
            self.assertTrue(all(w['phase'] == 'reset' and 0x1464ac910 <= int(w['instruction'], 16) < 0x1464acc4d for w in c['writes']))

    def test_base_table_or_getter_substitution_rejected(self):
        context = self.context()
        context['table'] = context['base_table']
        with self.assertRaisesRegex(ValueError, 'final slot differs'):
            load('verify-login-continuation-context').verify(context, ROOT)
        context = self.context()
        context['singleton'] = '0x14b5fe3d0'
        with self.assertRaisesRegex(ValueError, 'getter link differs'):
            load('verify-login-continuation-context').verify(context, ROOT)

    def test_changed_reset_callee_or_export_rejected(self):
        context = self.context()
        context['call_sites']['reset']['0x1464ac9fc'] = '0x14649fca1'
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            load('verify-login-continuation-context').verify(context, ROOT)
        context = self.context()
        context['exports']['run-c288c83765a6'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            load('verify-login-continuation-context').verify(context, ROOT)


class CurrentLoginContextTests(unittest.TestCase):
    def test_11318_whole_registered_context(self):
        from test_vampir_login_batch_support import verify_current
        verify_current(self, 'login-continuation', 'verify-login-continuation-context')


if __name__ == '__main__':
    unittest.main()
