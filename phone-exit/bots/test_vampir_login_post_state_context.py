import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')


class LoginPostStateContextTests(unittest.TestCase):
    def context(self):
        return json.loads((HERE / 'knowledge/native-contexts/login-post-state-11316.json').read_text('utf-8'))

    def test_wrapper_tail_abi_branches_and_stores(self):
        report = load('verify-login-post-state-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 44)
        self.assertFalse(report['network_used'] or report['profile_activated'])
        for case in report['cases']:
            s = case['settings']
            wrapper_gate = s['present'] and s['class_count'] >= s['class_index'] and s['class_match']
            reaches = case['direct'] or wrapper_gate
            operates = reaches and s['active'] and not s['busy'] and s['present'] and not s['occupied']
            self.assertEqual(len(case['target_entry']), int(reaches))
            self.assertEqual(case['slot'], 0 if operates else 0xaabbccdd)
            self.assertTrue(case['guards'])
            if not case['direct'] and s['present'] and not wrapper_gate:
                self.assertEqual(case['returned'], 0x28003030)
            else:
                # The callee writes AL; the wrapper does not define a Boolean RAX.
                self.assertEqual(case['returned'] & 255, int(operates))
            if reaches:
                target = case['target_entry'][0]
                self.assertTrue(target['service'])
                self.assertEqual(target['actor'], s['present'])
                self.assertEqual(target['flag'], s['flag'] if case['direct'] else 1)
                self.assertEqual(target['stack'], 0x38000)
            if operates:
                self.assertEqual(len(case['writes']), 1)
                write = case['writes'][0]
                self.assertEqual((write['offset'], write['size'], write['value']), ('0x250', 8, 0))
                self.assertTrue(0x144a2d8c0 <= int(write['instruction'], 16) < 0x144a2da42)
                self.assertIn('assign', case['events'])
                self.assertEqual('hide' in case['events'], s['mode'] != 3 and (s['predicate'] or s['fallback']))
                list_path = bool(s['list_match'] and (s['flag'] if case['direct'] else 1))
                virtuals = [name for name in case['events'] if name.startswith('virtual_')]
                self.assertEqual(virtuals, ['virtual_0x2e8', 'virtual_0x540'] if list_path else
                                 ['virtual_0x4c8', 'virtual_0x540', 'virtual_0x2e8'] if s['eligible'] else [])
                self.assertEqual('settle' in case['events'], not list_path)
                self.assertEqual('mark' in case['events'], not list_path and s['eligible'])
            else:
                self.assertFalse(case['writes'])
                self.assertNotIn('assign', case['events'])

    def test_changed_tail_or_callee_rejected(self):
        context = self.context()
        context['tail_calls'][0]['target'] = '0x144a2d8c1'
        with self.assertRaisesRegex(ValueError, 'tail link differs'):
            load('verify-login-post-state-context').verify(context, ROOT)
        context = self.context()
        context['call_sites']['wrapper']['0x146755559'] = '0x144a26c41'
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            load('verify-login-post-state-context').verify(context, ROOT)

    def test_corrupt_export_or_native_fixture_overlap_rejected(self):
        context = self.context()
        context['exports']['run-c0c472fc6e1c'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            load('verify-login-post-state-context').verify(context, ROOT)
        context = self.context()
        context['fixtures']['lookup'] = context['functions']['target']
        with self.assertRaisesRegex(ValueError, 'overlaps native code'):
            load('verify-login-post-state-context').verify(context, ROOT)


class CurrentLoginContextTests(unittest.TestCase):
    def test_11318_whole_registered_context(self):
        from test_vampir_login_batch_support import verify_current
        verify_current(self, 'login-post-state', 'verify-login-post-state-context')


if __name__ == '__main__':
    unittest.main()
