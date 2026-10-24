import json
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/character-record-11316.json'


class CharacterRecordContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_native_record_projection_and_failure_gates(self):
        report = load('verify-character-record-context').verify(self.context(), ROOT)
        self.assertEqual((len(report['cases']), len(report['truncated']), len(report['failures'])), (128, 201, 128))
        self.assertTrue(all(row['accepted'] for row in report['cases']))
        self.assertFalse(any(row['accepted'] for row in report['truncated'] + report['failures'] + report['boundaries']))
        self.assertEqual({row['boundary'] for row in report['boundaries']}, {'appearance_items_not_ported', 'optional_items_not_ported'})
        self.assertEqual(report['extra']['consumed'], 201)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])

    def test_scope_cannot_expand(self):
        for budget, scope in ((22, None), (22, 'other'), (23, 'character-record'), (32, 'character-record')):
            context = self.context()
            context.update(function_budget=budget, budget_scope=scope)
            with self.assertRaisesRegex(ValueError, 'function/export budget exceeded'):
                load('verify-character-record-context').verify(context, ROOT)

    def test_changed_input_dependency_rejected(self):
        context = self.context()
        context['native_input']['call_sites']['0x144aac2b9']['target'] = '0x144aac190'
        with self.assertRaisesRegex(ValueError, 'input callees differ'):
            load('verify-character-record-context').verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
