import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/login-prepare-metadata-11316.json'


class LoginPrepareMetadataContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_shared_metadata_projection_and_cleanup(self):
        report = load('verify-login-prepare-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 448)
        self.assertTrue(report['native_sdk_used'])
        self.assertTrue(report['native_metadata_used'])
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
        outputs = []
        for case in report['cases']:
            self.assertTrue(case['guards'])
            calls = case['metadata_calls']
            enabled = case['scenario'] not in ('sdk-disabled', 'sdk-absent', 'handles-absent', 'aux-absent')
            self.assertEqual(calls.get('collector', 0), int(enabled))
            backend, pattern, marketing = case['metadata_case']
            active = enabled and backend not in ('none', 'invalid')
            self.assertEqual(calls.get('writer', 0), int(active))
            self.assertEqual(calls.get('selector', 0), 27 * int(active))
            text = case['strings']['0xd8']
            if not active:
                self.assertEqual(text, '')
                continue
            self.assertEqual(text.count('"I_World":'), 2)
            self.assertEqual('"I_LogDes":' in text, marketing)
            self.assertEqual('"I_DeviceKey":' in text, case['scenario'] != 'main-absent')
            if pattern == 'unicode-quote':
                self.assertIn('Ж🙂', text)
            if case['empty']:
                # Metadata is not replaced by the empty caller-input fixture.
                self.assertTrue(text)
            outputs.append(text)
        self.assertGreater(len(set(outputs)), 4)

    def test_changed_collector_or_metadata_source_rejected(self):
        tool = load('verify-login-prepare-context')
        context = self.context()
        context['native_metadata']['source_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'integration source differs'):
            tool.verify(context, ROOT)
        context = self.context()
        context['native_metadata']['functions']['collector'] = '0x14560b0d1'
        with self.assertRaisesRegex(ValueError, 'absent from supplied exports'):
            tool.verify(context, ROOT)

    def test_changed_metadata_callee_rejected(self):
        context = self.context()
        context['native_metadata']['call_sites'][next(iter(context['native_metadata']['call_sites']))]['target'] = '0x1445cd9d1'
        with self.assertRaisesRegex(ValueError, 'Metadata call sites differ'):
            load('verify-login-prepare-context').verify(context, ROOT)


class CurrentLoginContextTests(unittest.TestCase):
    def test_11318_whole_registered_context(self):
        from test_vampir_login_batch_support import verify_current
        verify_current(self, 'login-prepare-metadata', 'verify-login-prepare-context')


if __name__ == '__main__':
    unittest.main()
