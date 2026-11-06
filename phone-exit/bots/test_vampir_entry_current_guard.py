"""Retained real current proofs stay source-bound without native re-execution."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CurrentEntryGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.guard = load('entry-current-check-guard')
        cls.index = load('knowledge-index')
        cls.root = Path('F:/PhoneExit Resources/Vampir')
        cls.sha = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
        cls.definitions = {row['id']: row for row in cls.index.read_json(HERE / 'knowledge/research-checks.json')['checks']}

    def test_real_both_package_inputs_and_outputs_are_retained_without_native(self):
        for identifier in sorted(self.guard.IDS):
            with self.subTest(identifier=identifier):
                definition = self.definitions[identifier]
                material, pointer = self.guard.retained(self.index, self.root, HERE / 'knowledge', definition, self.sha)
                self.assertGreaterEqual(len(material), 10)
                self.assertEqual(material[pointer['path']], pointer['sha256'])
                report = dict(definition=dict(check=definition, source_sha256=self.sha, artifacts=material),
                              entry_current_guard=dict(pointer=pointer))
                self.assertEqual(self.guard.runtime_inputs(self.index, self.root, report, identifier), {})
                reduced = dict(material)
                del reduced[next(name for name in material if name != pointer['path'])]
                report['definition']['artifacts'] = reduced
                with self.assertRaisesRegex(ValueError, 'lost retained inputs'):
                    self.guard.runtime_inputs(self.index, self.root, report, identifier)

    def test_corrupt_selected_proof_is_rejected_before_any_package_load(self):
        definition = self.definitions['character-list-current']
        pointer = self.index.read_json(HERE / 'knowledge/entry-native-current.json')['proofs']['character-list-current']
        original = self.index.digest
        with patch.object(self.index, 'digest', side_effect=lambda p:
                '0' * 64 if Path(p).resolve() == Path(pointer['path']).resolve() else original(p)):
            with self.assertRaisesRegex(ValueError, 'proof changed'):
                self.guard.retained(self.index, self.root, HERE / 'knowledge', definition, self.sha)


if __name__ == '__main__':
    unittest.main()
