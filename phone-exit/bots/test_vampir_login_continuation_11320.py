"""Current whole constructor/reset with explicit external helper fixtures."""
import copy
import json
import unittest
from pathlib import Path
from test_vampir_update_contracts import load, HERE


class LoginContinuation11320Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = json.loads((HERE / 'knowledge/native-contexts/login-continuation-11320.json').read_bytes())
        cls.tool = load('verify-login-continuation-context')
        cls.root = Path('F:/PhoneExit Resources/Vampir')
        cls.result = cls.tool.verify(cls.context, cls.root)

    def test_whole_constructor_getter_reset_and_guards(self):
        self.assertEqual(len(self.result['cases']), 8)
        self.assertTrue(all(c['guards'] for c in self.result['cases']))
        self.assertEqual(self.context['functions'], dict(constructor='0x1464a97b0', reset='0x1464afc70'))
        self.assertFalse(self.result['network_used'])
        self.assertFalse(self.result['profile_activated'])
        for case in self.result['cases']:
            self.assertEqual((case['field308'], case['flag']), (0, 0))
            self.assertTrue(all(w['phase'] == 'reset' for w in case['writes']))

    def test_table_getter_and_anchor_corruption_are_rejected(self):
        for kind in ('table', 'getter', 'anchor'):
            context = copy.deepcopy(self.context)
            if kind == 'table':
                context['table'] = context['base_table']
            elif kind == 'getter':
                context['singleton'] = '0x14b6014b0'
            else:
                context['anchors'][-1]['bytes'] = '90' + context['anchors'][-1]['bytes'][2:]
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.tool.verify(context, self.root)


if __name__ == '__main__':
    unittest.main()
