import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/character-list-records-11316.json'


class CharacterListRecordsContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_native_whole_list_preserves_distinct_records(self):
        report = load('verify-character-list-records-context').verify(self.context(), ROOT)
        self.assertEqual((len(report['cases']), len(report['truncated']), len(report['failures'])), (32, 291, 154))
        self.assertTrue(all(case['accepted'] for case in report['cases']))
        many = next(case for case in report['cases'] if case['count'] == 4)
        self.assertEqual(len({tuple(record['strings']) for record in many['records']}), 4)
        self.assertEqual(len({tuple(map(tuple, record['appearance_items'])) for record in many['records']}), 4)
        self.assertEqual([item['generation'] for item in many['copies']], [1, 2, 3, 4])
        self.assertFalse(any(case['accepted'] for case in report['truncated'] + report['failures'] + report['multi_truncated']))
        self.assertTrue(any(case['count'] > 0 for case in report['multi_truncated']))
        self.assertEqual(report['extra']['consumed'], 291)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])

    def test_scope_budget_cannot_expand(self):
        for budget, scope in ((34, None), (34, 'other'), (35, 'character-list-records'), (32, 'character-list-records')):
            context = self.context()
            context.update(function_budget=budget, budget_scope=scope)
            with self.assertRaisesRegex(ValueError, 'function/export budget exceeded'):
                load('verify-character-list-records-context').verify(context, ROOT)

    def test_changed_copy_call_rejected(self):
        context = self.context()
        context['call_sites']['list_record_thunk']['0x1456dce2c'] = '0x145783840'
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            load('verify-character-list-records-context').verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
