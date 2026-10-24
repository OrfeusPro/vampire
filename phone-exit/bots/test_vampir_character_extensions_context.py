import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/character-extensions-11316.json'


class CharacterExtensionsContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_native_collections_duplicates_and_failures(self):
        report = load('verify-character-extensions-context').verify(self.context(), ROOT)
        appearance, optional = report['components']
        self.assertEqual((appearance['roots'], len(appearance['cases']), len(appearance['truncated']), len(appearance['failures'])), (11, 5, 58, 42))
        self.assertEqual((optional['roots'], len(optional['cases']), len(optional['truncated']), len(optional['failures'])), (18, 19, 201, 94))
        self.assertTrue(any(row['rehashes'] for row in optional['cases']))
        self.assertTrue(any(len(row['values'] or []) == 8 and len(row['insertions']) == 8 for row in optional['cases']))
        for part in report['components']:
            self.assertTrue(all(row['accepted'] for row in part['cases']))
            self.assertFalse(any(row['accepted'] for row in part['truncated'] + part['failures']))
            self.assertEqual(part['budget']['status'], 'local_storage_budget')
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])

    def test_changed_callback_link_rejected(self):
        context = self.context()
        context['links']['appearance'][1][2] = '0x1456d2260'
        with self.assertRaisesRegex(ValueError, 'table link differs'):
            load('verify-character-extensions-context').verify_component(context, ROOT, 'appearance')

    def test_changed_insert_dependency_rejected(self):
        context = self.context()
        context['call_sites']['optional']['insert']['0x1456bd871'] = '0x1457841c0'
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            load('verify-character-extensions-context').verify_component(context, ROOT, 'optional')


if __name__ == '__main__':
    unittest.main()
