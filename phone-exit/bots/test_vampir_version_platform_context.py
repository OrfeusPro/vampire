import json
from pathlib import Path
import unittest
from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')


class VersionPlatformContextTests(unittest.TestCase):
    def test_11318_source_contexts(self):
        context=json.loads((HERE/'knowledge/native-contexts/version-platform-11318.json').read_text('utf-8'))
        report=load('verify-version-platform-context').verify(context,ROOT)
        self.assertEqual(len(report['cases']),116)
        self.assertFalse(report['network_used']);self.assertFalse(report['profile_activated'])

    def context(self):
        return json.loads((HERE / 'knowledge/native-contexts/version-platform-11316.json').read_text('utf-8'))

    def test_selector_store_and_lookup(self):
        report = load('verify-version-platform-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 116)
        selectors = [c for c in report['cases'] if c['kind'] == 'selector']
        self.assertEqual(len(selectors), 72)
        self.assertEqual({c['result'] for c in selectors}, {0, 1, 2, 3})
        self.assertEqual({c['truth'] for c in selectors}, {1, 128, 255})
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
        self.assertEqual(len([c for c in report['cases'] if c['kind'] == 'store']), 12)
        self.assertTrue(any(c['count'] == -1 and c['index'] == 0xffffffff
                            for c in report['cases'] if c['kind'] == 'lookup'))

    def test_changed_callee_and_export_are_rejected(self):
        context = self.context(); context['call_sites']['0x1445ce2e9'] = '0x0'
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            load('verify-version-platform-context').verify(context, ROOT)
        context = self.context(); context['exports']['run-09b30ec921d8'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            load('verify-version-platform-context').verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
