"""Create104 handler handoff, consumer branches and immutable reuse."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class CurrentCreateHandlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/verify-create-handler-current.py'
        spec = importlib.util.spec_from_file_location('create_handler_current', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.result = cls.tool.verify()

    def test_unchanged_composition_uses_receipt(self):
        with patch.object(self.tool, 'execute', side_effect=AssertionError('Unexpected handler replay')):
            self.assertEqual(self.tool.verify(), dict(self.result, reused=True))
        report = json.loads(Path(self.result['report']).read_bytes())
        self.assertEqual(report['cases'][1]['events'], ['insert_record', 'finalize'])
        self.assertEqual(report['cases'][0]['selected_key'], 0x1234)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['runtime_admitted'])

    def test_corrupt_selection_cannot_be_accepted_as_cached_success(self):
        report = json.loads(Path(self.result['report']).read_bytes())
        report['cases'][0]['selected_key'] = 0
        with self.assertRaisesRegex(ValueError, 'boundary differs'):
            self.tool.validate(report, report['definition'])

    def test_parent_proof_change_rejected_before_execution(self):
        context = json.loads(self.tool.CONTEXT.read_bytes())
        context['create_result_proof']['sha256'] = '0' * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'context.json'
            path.write_text(json.dumps(context), encoding='utf-8')
            with patch.object(self.tool, 'execute') as execute:
                with self.assertRaisesRegex(ValueError, 'parent proof changed'):
                    self.tool.verify(path)
                execute.assert_not_called()
