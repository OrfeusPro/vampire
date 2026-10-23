import json
from pathlib import Path
import unittest
from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')


class VersionSystemContextTests(unittest.TestCase):
    def context(self, name):
        return json.loads((HERE / 'knowledge/native-contexts' / ('version-' + name + '-11316.json')).read_text('utf-8'))

    def test_windows_cold_cached_failed_and_signed_tls_paths(self):
        report = load('verify-version-windows-context').verify(self.context('windows'), ROOT)
        self.assertEqual(len(report['cases']), 48)
        failure = next(c for c in report['cases'] if c['profile'] == 'failed-version')
        self.assertEqual(failure['result'], '')
        self.assertNotIn('format', failure['events'])
        cached = next(c for c in report['cases'] if c['profile'] == 'other-thread')
        self.assertEqual(cached['events'], ['acquire', 'wide_string', 'cookie_check'])
        self.assertTrue(any(c['result'] == '6.3.9600.255.65535.64bit' for c in report['cases']))
        self.assertFalse(report['host_identity_read'])
        self.assertFalse(report['network_used'])

    def test_cpu_native_getters_trim_and_two_part_projection(self):
        report = load('verify-version-cpu-context').verify(self.context('cpu'), ROOT)
        self.assertEqual(len(report['cases']), 72)
        self.assertTrue(any(c['result'] == 'Vendor|Spaced CPU' for c in report['cases']))
        self.assertTrue(any(c['result'] == 'GenuineIntel|A|B|C' for c in report['cases']))
        self.assertTrue(any(c['result'] == 'GenuineIntel|A' and '\0' in c['brand'] for c in report['cases']))
        self.assertTrue(any(c['result'] == '|' for c in report['cases']))
        self.assertTrue(all(c['space_calls'] > 0 for c in report['cases']))
        self.assertFalse(report['host_identity_read'])
        self.assertFalse(report['network_used'])

    def test_changed_exports_and_callees_are_rejected(self):
        for name in ('windows', 'cpu'):
            tool = load('verify-version-' + name + '-context')
            context = self.context(name); context['exports']['run-09b30ec921d8'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'export SHA changed'): tool.verify(context, ROOT)
            context = self.context(name); context['call_sites'][next(iter(context['call_sites']))] = '0x0'
            with self.assertRaisesRegex(ValueError, 'call sites differ'): tool.verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
