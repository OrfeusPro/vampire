import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/character-list-handler-11316.json'


class CharacterListHandlerContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_gate_publication_preference_and_empty_list(self):
        report = load('verify-character-list-handler-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 101)
        self.assertEqual(report['empty_request'], dict(packet_id=101, writer_returned=True, packet_archive_unchanged=True))
        published = [case for case in report['cases'] if case['published']]
        self.assertEqual(len(published), 15)
        self.assertTrue(all(case['code'] == 0 and case['policy'] == 1 for case in published))
        self.assertTrue(all(case['selected_index'] == 0 for case in published if not case['ids']))
        duplicate = next(case for case in published if case['ids'] == [11, 22, 22, 33])
        self.assertEqual(duplicate['selected_index'], 1)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])

    def test_changed_registration_rejected(self):
        context = self.context()
        context['bindings']['handler_table'] = '0x149dc6690'
        with self.assertRaisesRegex(ValueError, 'registration table/ID differs'):
            load('verify-character-list-handler-context').verify(context, ROOT)

    def test_changed_gate_callee_rejected(self):
        context = self.context()
        context['call_sites']['handler']['0x1467963ec'] = '0x1467ce030'
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            load('verify-character-list-handler-context').verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
