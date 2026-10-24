import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/character-list-envelope-11316.json'


class CharacterListEnvelopeContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_empty_envelope_requires_complete_tail(self):
        report = load('verify-character-list-envelope-context').verify(self.context(), ROOT)
        self.assertEqual((len(report['cases']), len(report['truncated']), len(report['failures'])), (24, 38, 7))
        self.assertTrue(all(r['accepted'] and r['count'] == 0 and r['consumed'] == 38 for r in report['cases']))
        self.assertFalse(any(r['accepted'] for r in report['truncated'] + report['failures'] + report['nonempty']))
        self.assertEqual({r['status'] for r in report['nonempty']}, {'count_budget', 'record_reader_not_ported'})
        self.assertEqual(report['extra']['consumed'], 38)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])

    def test_changed_vector_link_rejected(self):
        context = self.context()
        context['bindings']['vector_table'] = '0x149928a48'
        with self.assertRaisesRegex(ValueError, 'table link differs'):
            load('verify-character-list-envelope-context').verify(context, ROOT)

    def test_changed_scalar_dependency_rejected(self):
        context = self.context()
        context['call_sites']['u32']['0x144aac2b9'] = '0x144aac190'
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            load('verify-character-list-envelope-context').verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
