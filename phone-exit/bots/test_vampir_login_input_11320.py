"""Actual input scalar readers integrated with the current whole LoginResult."""
import copy
import json
import unittest
from pathlib import Path
from test_vampir_update_contracts import load, HERE


class LoginInput11320Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load('verify-login-input-11320')
        cls.context = json.loads((HERE / 'knowledge/native-contexts/login-input-11320.json').read_bytes())
        cls.root = Path('F:/PhoneExit Resources/Vampir')
        cls.result = cls.tool.verify(cls.context, cls.root)

    def test_full_projection_bool_normalization_and_each_truncation(self):
        self.assertEqual(len(self.result['cases']), 128)
        self.assertEqual(len(self.result['truncated']), 367)
        self.assertTrue(all(c['returned'] == 1 and c['guards'] for c in self.result['cases']))
        self.assertTrue(all(c['returned'] == 0 and c['guards'] for c in self.result['truncated']))
        self.assertEqual(self.result['trailing']['size'] - self.result['trailing']['consumed'], 5)
        self.assertFalse(self.result['network_used'])
        self.assertFalse(self.result['runtime_activated'])

    def test_wrong_scalar_table_and_base_leaf_are_rejected(self):
        changed = copy.deepcopy(self.context)
        changed['input']['table'] = changed['packet_table']
        with self.assertRaisesRegex(ValueError, 'virtual slot differs'):
            self.tool.verify(changed, self.root)
        changed = copy.deepcopy(self.context)
        changed['leaves']['0x144aaced0'] = '90' + changed['leaves']['0x144aaced0'][2:]
        with self.assertRaises(ValueError):
            self.tool.verify(changed, self.root)


if __name__ == '__main__':
    unittest.main()
