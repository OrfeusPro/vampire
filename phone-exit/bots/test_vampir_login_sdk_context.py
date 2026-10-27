import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/login-prepare-sdk-11316.json'


class LoginSdkContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_native_getters_in_whole_login(self):
        report = load('verify-login-prepare-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 2016)
        self.assertTrue(report['native_sdk_used'])
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
        keys = [field['key'] for field in report['metadata_fields']]
        self.assertEqual(len(keys), 27)
        self.assertEqual(len(set(keys)), 26)
        self.assertEqual(keys.count('I_World'), 2)
        self.assertEqual(keys[-3:], ['I_NMCPU', 'I_NMRAM', 'I_NMVGA'])
        self.assertEqual({c['cache_case'] for c in report['cases']}, {'warm', 'resolve', 'absent'})
        for case in report['cases']:
            self.assertTrue(case['guards'])
            active = case['sdk_event']
            calls = case['native_calls']
            self.assertEqual(calls.get('owner_number'), 2 + int(active))
            self.assertEqual(calls.get('language'), 1)
            self.assertEqual(calls.get('sdk_main_text', 0), int(active))
            self.assertEqual(calls.get('sdk_value', 0), int(active))
            self.assertIn(case['integers']['0x130'], (0, 1))
            if active and not case['empty']:
                self.assertEqual(case['strings']['0xa0'], 'retained-sdk-value-界' if case['cache_case'] == 'absent' else 'sdk-cache-Ж🙂')
            if case['cache_case'] == 'absent':
                self.assertEqual(case['strings']['0x30'], '')
            if case['scenario'] == 'sdk-absent' and not case['empty']:
                self.assertEqual(case['integers']['0x130'], 1)

    def test_changed_leaf_or_inner_call_rejected(self):
        tool = load('verify-login-prepare-context')
        context = self.context()
        leaf = context['native_sdk']['leaves']['0x145ccd310']
        leaf['bytes'] = '807908040f94c0c3'
        with self.assertRaisesRegex(ValueError, 'instruction differs from source'):
            tool.verify(context, ROOT)
        context = self.context()
        context['native_sdk']['call_sites'][next(iter(context['native_sdk']['call_sites']))]['target'] = '0x144529d61'
        with self.assertRaisesRegex(ValueError, 'getter call sites differ'):
            tool.verify(context, ROOT)
        context = self.context()
        context['native_sdk']['metadata']['consumer'] = '0x145601841'
        with self.assertRaisesRegex(ValueError, 'metadata key consumer link differs'):
            tool.verify(context, ROOT)

    def test_changed_sdk_export_or_native_binding_rejected(self):
        tool = load('verify-login-prepare-context')
        context = self.context()
        context['native_sdk']['exports']['run-2c9766b1ab08'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            tool.verify(context, ROOT)
        context = self.context()
        context['native_sdk']['native_names'].remove('language')
        with self.assertRaisesRegex(ValueError, 'native bindings differ'):
            tool.verify(context, ROOT)


class CurrentLoginContextTests(unittest.TestCase):
    def test_11318_whole_registered_context(self):
        from test_vampir_login_batch_support import verify_current
        verify_current(self, 'login-prepare-sdk', 'verify-login-prepare-context')


if __name__ == '__main__':
    unittest.main()
