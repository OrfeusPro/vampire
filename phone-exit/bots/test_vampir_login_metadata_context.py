import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/login-metadata-11316.json'


class LoginMetadataContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_whole_metadata_pipeline(self):
        report = load('verify-login-metadata-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 288)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
        self.assertEqual(report['field_map']['I_ConnectIP'], 0xe0)
        self.assertEqual(report['field_map']['I_NMCPU'], 0x1f0)
        for case in report['cases']:
            self.assertTrue(case['guards'])
            if case['backend'] in ('none', 'invalid'):
                self.assertEqual(case['output'], '')
                continue
            self.assertEqual(case['output'].count('"I_World":'), 2)
            self.assertEqual(case['native_calls']['selector'], 27)
            self.assertEqual(case['mapping']['I_NMDeviceKey'], 'nm-key-fixture')
            self.assertEqual('"I_DeviceKey":' in case['output'], case['optional_device'])
            self.assertEqual('"I_LogDes":' in case['output'], case['marketing'])
            if case['pattern'] in ('empty', 'omit-nid', 'omit-gates'):
                self.assertNotIn('I_NMNIDChannelType', case['mapping'])
            if case['pattern'] == 'empty':
                self.assertNotIn('I_NMCharacterID', case['mapping'])
            if case['pattern'] == 'unicode-quote':
                self.assertIn('Ж🙂', case['output'])
                # Formatting is an explicit substitution fixture, not proven JSON escaping.
                self.assertIn('q"\\', case['output'])

    def test_changed_source_or_export_rejected(self):
        tool = load('verify-login-metadata-context')
        context = self.context()
        context['source_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'source path differs'):
            tool.verify(context, ROOT)
        context = self.context()
        context['exports']['run-8ce3965fd27d'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            tool.verify(context, ROOT)

    def test_changed_callee_or_selector_order_rejected(self):
        tool = load('verify-login-metadata-context')
        context = self.context()
        context['call_sites'][next(iter(context['call_sites']))]['target'] = '0x1445cd9d1'
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            tool.verify(context, ROOT)
        context = self.context()
        context['collector_order'][0] = 'I_Unknown'
        with self.assertRaisesRegex(ValueError, 'collector projection differs'):
            tool.verify(context, ROOT)


class CurrentLoginContextTests(unittest.TestCase):
    def test_11318_whole_registered_context(self):
        from test_vampir_login_batch_support import verify_current
        verify_current(self, 'login-metadata', 'verify-login-metadata-context')


if __name__ == '__main__':
    unittest.main()
