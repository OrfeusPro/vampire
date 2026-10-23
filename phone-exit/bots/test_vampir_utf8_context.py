import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE/'knowledge/native-contexts/utf8-11316.json'


class Utf8ContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_native_conversion_and_capacity_boundaries(self):
        report = load('verify-utf8-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 142)
        self.assertEqual(len(report['scalar_cases']), 80)
        self.assertTrue(all(c['guards'] for c in report['cases']+report['scalar_cases']))
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
        emoji = [c for c in report['cases'] if c['vector'] == 6]
        self.assertEqual(next(c for c in emoji if c['capacity'] == 4)['output_hex'], 'f09f9982')
        self.assertEqual(next(c for c in emoji if c['capacity'] == 3)['output_hex'], '')
        for scalar in (0xd800, 0xfffe, 0x110000):
            c = next(c for c in report['scalar_cases'] if c['scalar'] == scalar and c['capacity'] == 1)
            self.assertEqual(c['output_hex'], '3f')

    def test_corrupt_exports_and_leaf_are_rejected(self):
        tool = load('verify-utf8-context')
        context = self.context()
        first = next(iter(context['exports']))
        context['exports'][first] = '0'*64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            tool.verify(context, ROOT)
        context = self.context()
        context['encoder_leaf']['size'] += 1
        with self.assertRaisesRegex(ValueError, 'leaf bounds or SHA'):
            tool.verify(context, ROOT)

    def test_wrong_source_and_encoder_link_are_rejected(self):
        tool = load('verify-utf8-context')
        context = self.context()
        context['source_sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'source path differs'):
            tool.verify(context, ROOT)
        context = self.context()
        context['bindings']['encoder'] = '0x14143f321'
        with self.assertRaises(ValueError):
            tool.verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
