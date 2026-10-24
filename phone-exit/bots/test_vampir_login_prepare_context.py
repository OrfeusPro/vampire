import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/login-prepare-11316.json'


class LoginPrepareContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_whole_login_projection_and_post_send_lifecycle(self):
        report = load('verify-login-prepare-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 672)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
        cases = report['cases']
        self.assertTrue(all(c['guards'] for c in cases))
        self.assertEqual({c['selector'] for c in cases}, {0, 1, 2, 3, 4, 255})
        self.assertEqual({c['send_return'] for c in cases}, {0, 1})
        self.assertEqual({c['integers']['0x99'] for c in cases}, {0, 1, 3, 6})
        self.assertEqual({c['integers']['0x98'] for c in cases}, {0, 1, 2, 3, 5})
        for case in cases:
            self.assertEqual(case['strings']['0x110'], '32283C4C6485307BCF524765A84409C3')
            self.assertEqual(case['integers']['0xf8'], 207)
            self.assertEqual(case['integers']['0x128'], 0)
            self.assertEqual(case['lifecycle'][-1], 'destructor')
            if case['scenario'] == 'sdk-disabled':
                self.assertEqual(case['strings']['0x30'], '')
                self.assertEqual(case['strings']['0xa0'], '')
                self.assertEqual(case['strings']['0xd8'], '')
                self.assertEqual(case['integers']['0x130'], 0)
                self.assertFalse(case['sdk_event'])
            elif case['scenario'] == 'sdk-absent':
                # Enabled flag manager is independent of the optional SDK manager.
                self.assertEqual(case['integers']['0x130'], 0 if case['empty'] else 0x80)
                self.assertFalse(case['sdk_event'])

    def test_corrupt_source_and_export_rejected(self):
        tool = load('verify-login-prepare-context')
        context = self.context()
        context['source_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'source path differs'):
            tool.verify(context, ROOT)
        context = self.context()
        context['exports']['run-7c5a462e9d0c'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            tool.verify(context, ROOT)

    def test_changed_callee_table_or_fixture_rejected(self):
        tool = load('verify-login-prepare-context')
        context = self.context()
        context['call_sites'][next(iter(context['call_sites']))]['target'] = '0x143c19621'
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            tool.verify(context, ROOT)
        context = self.context()
        context['packet_table'] = '0x1499263d1'
        with self.assertRaisesRegex(ValueError, 'table link differs'):
            tool.verify(context, ROOT)
        context = self.context()
        context['fixtures']['sdk_mode'] = '0x14560aed1'
        with self.assertRaisesRegex(ValueError, 'fixture coverage differs'):
            tool.verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
