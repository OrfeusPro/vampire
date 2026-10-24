import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/version-result-11316.json'


class VersionResultContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_reader_matches_runtime_and_stops_on_failure(self):
        report = load('verify-version-result-context').verify(self.context(), ROOT)
        self.assertEqual((len(report['cases']), len(report['truncated']), len(report['failures'])), (32, 17, 5))
        self.assertTrue(all(row['returned'] == 0 for row in report['truncated'] + report['failures']))
        self.assertEqual(report['extra']['consumed'], 17)
        self.assertEqual(len(report['construction_cases']), 72)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])

    def test_wrong_packet_reader_is_rejected(self):
        context = self.context()
        context['reader'] = '0x1456dc140'
        with self.assertRaisesRegex(ValueError, 'absent from supplied exports|reader slot differs'):
            load('verify-version-result-context').verify(context, ROOT)

    def test_changed_archive_dependency_is_rejected(self):
        context = self.context()
        context['native_input']['call_sites']['0x144aac2b9']['target'] = '0x144aac190'
        with self.assertRaisesRegex(ValueError, 'Input archive call sites differ'):
            load('verify-version-result-context').verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
