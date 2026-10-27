import json
import math
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')


class LoginResultHandlerContextTests(unittest.TestCase):
    def context(self):
        return json.loads((HERE / 'knowledge/native-contexts/login-result-handler-11316.json').read_text('utf-8'))

    def test_native_success_error_writes_and_gates(self):
        report = load('verify-login-result-handler-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 38)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
        for case in report['cases']:
            actions = [e['action'] for e in case['events']]
            settings = case['settings']
            early = bool(settings.get('peer_flag') and 0 < case['field48'] < 32768)
            success = case['code'] == 0 and not early
            state_writes = [w for w in case['writes'] if w['region'] == 'state']
            controller_writes = [w for w in case['writes'] if w['region'] == 'controller']
            self.assertTrue(case['guards'])
            for e in case['events']:
                if e['action'] == 'native_gate':
                    self.assertEqual(e['packet_id'], 4)
                    self.assertEqual(e['code'], case['code'])
                if e['action'] == 'native_gate_return':
                    self.assertEqual(e['value'], int(case['code'] == 0))
            if success:
                self.assertEqual(case['state']['text'], 'fixture')
                base = 0x1234000000000000
                expected = dict(zip(('0x38', '0x88', '0xb0', '0xc0', '0xd0', '0xe0'), (base+1, base+1, base+4, base+5, base+6, base+7)))
                self.assertEqual(case['state']['qwords'], expected)
                self.assertEqual(case['state']['flags'], {'0xa0': 1, '0xe8': 1})
                self.assertEqual({w['offset']: w['value'] for w in state_writes}, dict(expected, **{'0xa0': 1, '0xe8': 1}))
                self.assertEqual(len(state_writes), 8)
                self.assertTrue(all(0x14679aec0 <= int(w['instruction'], 16) < 0x14679b486 for w in state_writes))
                signed = case['raw16'] if case['raw16'] < 32768 else case['raw16'] - 65536
                self.assertEqual(case['derived'], math.floor(signed * 600000000.0 + 0.5))
                self.assertEqual(case['controller_server'], [42, 42])
                self.assertEqual(len(controller_writes), 0 if settings.get('previous_server') == 42 else 2)
                self.assertIn('post_state', actions)
                self.assertIn('virtual_view', actions)
                self.assertEqual('flag138' in actions, settings.get('flag138', 1) == 1)
                callbacks = bool(settings.get('sdk_enabled') and settings.get('manager_present', True) and settings.get('sdk_callbacks'))
                self.assertEqual('virtual_sdk' in actions, callbacks)
                self.assertEqual('sdk_a0' in actions, callbacks)
                self.assertEqual('sdk_final' in actions, bool(settings.get('sdk_enabled') and settings.get('manager_present', True) and settings.get('auth_present')))
            else:
                self.assertFalse(state_writes or controller_writes)
                self.assertEqual(case['state']['text'], 'before')
                self.assertEqual(case['controller_server'], [7, 7])
                self.assertNotIn('post_state', actions)
                self.assertEqual(case['special22'], int(case['code'] == 22))
                if early:
                    self.assertEqual(actions[-2:], ['early', 'virtual_exit'])
                elif case['code'] in (14, 22, 37):
                    self.assertIn('dedicated_error', actions)
                elif case['code'] in (9818, 9819, 90021):
                    self.assertIn('error_finish', actions)
                    if not settings.get('optional_object', True):
                        self.assertNotIn('error_9818', actions)
                        self.assertNotIn('error_90021', actions)
                elif case['code'] == 54:
                    self.assertEqual(actions, ['popup54'])
                elif case['code'] == 9400:
                    self.assertIn('error9400', actions)
                else:
                    self.assertIn('disconnect', actions)
                    self.assertIn('popup' if settings.get('message') else 'virtual_exit', actions)
                    self.assertEqual('gate_error' in actions, not settings.get('gate_state'))

    def test_changed_gate_call_or_export_rejected(self):
        context = self.context()
        site = next(k for k, v in context['call_sites']['handler'].items() if v == '0x1467cd7b0')
        context['call_sites']['handler'][site] = '0x1467cd7b1'
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            load('verify-login-result-handler-context').verify(context, ROOT)
        context = self.context()
        context['exports']['run-eff5f37ca91c'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            load('verify-login-result-handler-context').verify(context, ROOT)

    def test_fixtures_cannot_replace_handler_or_gate(self):
        context = self.context()
        context['fixtures']['gate_error'] = context['functions']['gate']
        with self.assertRaisesRegex(ValueError, 'overlaps native code'):
            load('verify-login-result-handler-context').verify(context, ROOT)


class CurrentLoginContextTests(unittest.TestCase):
    def test_11318_whole_registered_context(self):
        from test_vampir_login_batch_support import verify_current
        verify_current(self, 'login-result-handler', 'verify-login-result-handler-context')


if __name__ == '__main__':
    unittest.main()
