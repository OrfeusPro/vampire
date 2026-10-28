"""Whole current LoginResult layout and real nested dispatch, primitive fixtures."""
import copy
import json
import unittest
from pathlib import Path
from test_vampir_update_contracts import load, HERE


class LoginNested11320Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load('verify-login-nested-11320')
        cls.context = json.loads((HERE / 'knowledge/native-contexts/login-nested-11320.json').read_bytes())
        cls.root = Path('F:/PhoneExit Resources/Vampir')
        cls.result = cls.tool.verify(cls.context, cls.root)

    def test_constructor_nested_readers_and_all_failure_positions(self):
        self.assertEqual(len(self.result['cases']), 232)
        self.assertEqual(len(self.result['operations']), 28)
        self.assertTrue(all(c['guards'] for c in self.result['cases']))
        self.assertEqual({c['fail_at'] for c in self.result['cases'] if c['fail_at'] is not None}, set(range(28)))
        self.assertEqual(self.result['operations'][-3:], [('string', 0x140), ('raw32', 0x150), ('raw32', 0x154)])
        self.assertFalse(self.result['network_used'])
        self.assertFalse(self.result['runtime_activated'])

    def test_wrong_nested_table_and_dispatch_bytes_rejected(self):
        changed = copy.deepcopy(self.context)
        changed['time_table'] = changed['period_table']
        with self.assertRaisesRegex(ValueError, 'table/reader link'):
            self.tool.verify(changed, self.root)
        changed = copy.deepcopy(self.context)
        changed['leaves']['0x144aad250'] = '90' + changed['leaves']['0x144aad250'][2:]
        with self.assertRaises(ValueError):
            self.tool.verify(changed, self.root)


if __name__ == '__main__':
    unittest.main()
