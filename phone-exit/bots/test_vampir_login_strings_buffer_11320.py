"""Current native UTF8/string readers and concrete buffer construction."""
import copy
import json
import unittest
from pathlib import Path
from test_vampir_update_contracts import load, HERE


class LoginStringsBuffer11320Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load('verify-login-input-11320')
        cls.context = json.loads((HERE / 'knowledge/native-contexts/login-strings-buffer-11320.json').read_bytes())
        cls.root = Path('F:/PhoneExit Resources/Vampir')
        cls.result = cls.tool.verify(cls.context, cls.root)

    def test_native_strings_buffer_truncation_and_storage_boundaries(self):
        self.assertEqual((len(self.result['cases']), len(self.result['truncated']), len(self.result['boundaries']), len(self.result['special'])), (128, 367, 4, 6))
        self.assertTrue(self.result['native_strings'])
        self.assertTrue(self.result['native_buffer_construction'])
        self.assertTrue(all(c['guards'] for k in ('cases', 'truncated', 'boundaries', 'special') for c in self.result[k]))
        self.assertFalse(self.result['runtime_activated'])
        self.assertFalse(self.result['network_used'])

    def test_special_inputs_have_explicit_source_bound_outcomes(self):
        for case in self.result['special']:
            self.assertEqual(case['returned'], 1)
            self.assertEqual(case['consumed'], case['size'])
            # NUL truncation here includes the explicitly modeled C-string assign boundary.
            self.assertEqual(case['first_string_utf16'], '61000000' if case['input_hex'] == '610062' else '3f000000')

    def test_exact_context_regeneration_from_reviewed_links(self):
        self.assertEqual(load('generate-login-strings-buffer-11320').generate(self.root), self.context)

    def test_unreviewed_budget_and_changed_calls_are_rejected(self):
        context = copy.deepcopy(self.context)
        context['function_budget'] = 21
        with self.assertRaises(ValueError):
            self.tool.verify(context, self.root)
        context = copy.deepcopy(self.context)
        first = next(iter(context['input']['call_sites']))
        context['input']['call_sites'][first] = {'target': '0x140000001'}
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            self.tool.verify(context, self.root)


if __name__ == '__main__':
    unittest.main()
