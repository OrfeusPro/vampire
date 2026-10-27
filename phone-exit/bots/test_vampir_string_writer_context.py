import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE/'knowledge/native-contexts/string-writer-11316.json'


class StringWriterContextTests(unittest.TestCase):
    def test_current_11318_context_and_metadata(self):
        context = json.loads((HERE/'knowledge/native-contexts/string-writer-11318.json').read_text('utf-8'))
        tool = load('verify-string-writer-context')
        report = tool.verify(context, ROOT)
        self.assertEqual(len(report['cases']), 228)
        self.assertTrue(all(c['guards'] for c in report['cases']))
        self.assertFalse(report['network_used']); self.assertFalse(report['profile_activated'])
        context['writer_metadata']['cookie'] = '0x14b273781'
        with self.assertRaisesRegex(ValueError, 'cookie source link'):
            tool.verify(context, ROOT)
        del context['writer_metadata']
        with self.assertRaisesRegex(ValueError, 'explicit writer metadata'):
            tool.verify(context, ROOT)

    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_native_string_writer_boundaries_and_failure_cleanup(self):
        report = load('verify-string-writer-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 228)
        self.assertTrue(all(c['guards'] for c in report['cases']))
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
        self.assertEqual({c['archive_result'] for c in report['cases']}, {0, 1, 128, 255})
        self.assertTrue(all(c['utf8_bytes'] == 0 for c in report['cases'] if c['count'] == 0))
        short = next(c for c in report['cases'] if c['utf8_bytes'] == 15)
        self.assertEqual(short['allocations'], {})
        self.assertEqual(short['cpp_capacity'], 15)
        middle = next(c for c in report['cases'] if c['utf8_bytes'] == 127)
        self.assertEqual(set(middle['allocations']), {'cpp'})
        long = next(c for c in report['cases'] if c['utf8_bytes'] == 128)
        self.assertEqual(set(long['allocations']), {'cpp', 'utf8'})
        aligned = next(c for c in report['cases'] if c['utf8_bytes'] == 4095)
        self.assertEqual(aligned['allocations']['cpp'], 4135)

    def test_wrong_export_and_leaf_rejected(self):
        tool = load('verify-string-writer-context')
        context = self.context()
        context['exports'][next(iter(context['exports']))] = '0'*64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            tool.verify(context, ROOT)
        context = self.context()
        context['encoder_leaf']['size'] += 1
        with self.assertRaisesRegex(ValueError, 'leaf bounds or SHA'):
            tool.verify(context, ROOT)

    def test_wrong_source_or_archive_link_rejected(self):
        tool = load('verify-string-writer-context')
        context = self.context()
        context['source_sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'source path differs'):
            tool.verify(context, ROOT)
        context = self.context()
        context['fixtures']['archive_slot'] = 0x30
        with self.assertRaisesRegex(ValueError, 'archive slot'):
            tool.verify(context, ROOT)
        context = self.context()
        context['fixtures']['utf8_free'] = '0x141483081'
        with self.assertRaisesRegex(ValueError, 'direct calls differ'):
            tool.verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
