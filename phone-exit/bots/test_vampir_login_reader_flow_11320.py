"""Source-bound whole-reader flow and candidate rejection, without game actions."""
import copy
import json
import unittest
from pathlib import Path
from test_vampir_update_contracts import load


class LoginReaderFlow11320Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load('verify-login-reader-flow-11320')
        cls.root = Path('F:/PhoneExit Resources/Vampir')
        cls.spec = json.loads((cls.tool.HERE / 'knowledge/native-contexts/login-reader-flow-11320.json').read_bytes())
        path = cls.root / cls.spec['discovery']
        if cls.tool.load('discover-login-result-11320').digest(path) != cls.spec['discovery_sha256']:
            raise ValueError('Reviewed reader discovery changed')
        cls.discovery = json.loads(path.read_bytes())
        cls.result = cls.tool.verify(cls.discovery, cls.spec['exports'], cls.root)

    def test_all_operations_short_circuit_abi_and_memory(self):
        self.assertEqual(len(self.result['operations']), 23)
        self.assertEqual(len(self.result['cases']), 96)
        self.assertTrue(all(c['guards'] for c in self.result['cases']))
        self.assertEqual({c['fail_at'] for c in self.result['cases'] if c['fail_at'] is not None}, set(range(23)))
        self.assertFalse(self.result['runtime_activated'])
        self.assertFalse(self.result['network_used'])

    def test_two_independent_links_resolve_one_handler(self):
        self.assertEqual(self.result['handler_link']['handler'], '0x14679e2d0')
        self.assertEqual(self.result['handler_link']['candidate_count'], 211)
        self.assertFalse(self.result['handler_link']['semantic_verification'])
        self.assertEqual(self.discovery['constructor_candidates'], ['0x1456d7660'])
        self.assertNotIn('0x1456da120', self.discovery['constructor_candidates'])

    def test_changed_destination_and_handler_are_rejected(self):
        changed = copy.deepcopy(self.discovery)
        changed['operations'][0]['destination'] = 'rdx, [rcx + 0x14]'
        with self.assertRaises(ValueError):
            self.tool.verify(changed, self.spec['exports'], self.root)
        changed = copy.deepcopy(self.discovery)
        changed['handler_candidates'] = ['0x1467a0610']
        with self.assertRaisesRegex(ValueError, 'Missing/ambiguous'):
            self.tool.resolve_handler(changed, self.root)


if __name__ == '__main__':
    unittest.main()
