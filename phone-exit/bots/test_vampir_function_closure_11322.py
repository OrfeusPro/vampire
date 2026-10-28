"""Real five-function source20/source22 equivalence with full export coverage."""
import copy
import json
import unittest
from pathlib import Path
from test_vampir_update_contracts import load, HERE


class FunctionClosure11322Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load('verify-function-closure-11322')
        cls.root = Path('F:/PhoneExit Resources/Vampir')
        cls.context = json.loads((HERE / 'knowledge/native-contexts/function-closure-11322.json').read_bytes())
        cls.result = cls.tool.verify(cls.context, cls.root)

    def test_five_full_instruction_and_dependency_closures(self):
        self.assertEqual(self.result['verified'], 5)
        self.assertEqual(len(self.result['coverage']), 10)
        self.assertEqual(self.result['scope'], 'function_only')
        self.assertFalse(self.result['runtime_activated'])
        self.assertFalse(self.result['network_used'])

    def test_graph_recipe_uses_latest_reviewed_base_and_preserves_new_bindings(self):
        model = json.loads((HERE / 'knowledge/update-contracts.json').read_bytes())
        contract = next(c for c in model['contracts'] if c['id'] == 'game-version')
        recipe = next(r for r in contract['recipes'] if r['key'] == 'utf8-length')
        versions = load('function-reuse-plan').SOURCES
        latest = next(sha for _, sha in sorted(versions.items(), key=lambda row: int(row[0]), reverse=True)
                      if 'utf8-length' in contract['bindings'].get(sha, {}))
        self.assertEqual(recipe['baseline_sha256'], latest)
        self.assertEqual(recipe['baseline_address'], contract['bindings'][latest]['utf8-length'])
        self.assertEqual(contract['bindings'][self.tool.SOURCE]['utf8-length'], '0x14144c5b0')

    def test_wrong_target_and_changed_export_are_rejected(self):
        context = copy.deepcopy(self.context)
        context['functions']['f-14143bd90'] = '0x14143ba00'
        with self.assertRaisesRegex(ValueError, 'target bindings differ'):
            self.tool.verify(context, self.root)
        context = copy.deepcopy(self.context)
        first = next(iter(context['exports']))
        context['exports'][first] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export changed'):
            self.tool.verify(context, self.root)


if __name__ == '__main__':
    unittest.main()
