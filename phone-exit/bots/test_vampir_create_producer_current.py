"""Source transfer and cache boundaries for the current Create/JSON producer."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
TOOLS = HERE / 'resource-tools/vampir'


def load():
    spec = importlib.util.spec_from_file_location('create_producer_current', TOOLS / 'verify-create-producer-current.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


class CreateProducerCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load()
        cls.pointer = cls.tool.verify()
        cls.report = json.loads(Path(cls.pointer['report']).read_bytes())

    def test_complete_scope_and_warm_reuse(self):
        result = self.report
        self.assertEqual(result['core_roots'], 15)
        self.assertEqual(result['core_relocations'], 82)
        self.assertEqual(result['inherited_cases'], dict(producer=37, json=36, class_source=144))
        self.assertEqual(len(result['numeric_methods']), 4)
        self.assertTrue(result['source_ui_constructor_verified'])
        self.assertFalse(result['native_execution'])
        self.assertTrue(result['native_proofs_reused'])
        with patch.object(self.tool, 'transfer', side_effect=AssertionError('repeated source analysis')):
            warm = self.tool.verify()
        self.assertTrue(warm['reused'])
        self.assertEqual(warm['sha256'], self.pointer['sha256'])

    def test_changed_binding_and_data_are_concrete_blockers(self):
        context, parents, _ = self.tool.definition(self.tool.CONTEXT, self.tool.ROOT)
        for field in ('roots', 'constants'):
            changed = copy.deepcopy(context)
            if field == 'roots':
                changed[field]['0x146449dc0'] = '0x14644bc31'
                expected = 'root binding'
            else:
                changed[field]['0x149a3f328'] = '00' * 20
                expected = 'literal/sentinel'
            with self.assertRaisesRegex(ValueError, expected):
                self.tool.transfer(changed, parents, self.tool.ROOT)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'context.json'
            changed = copy.deepcopy(context)
            changed['source_sha256'] = '0' * 64
            path.write_text(json.dumps(changed), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'context/source'):
                self.tool.definition(path, self.tool.ROOT)


if __name__ == '__main__':
    unittest.main()
