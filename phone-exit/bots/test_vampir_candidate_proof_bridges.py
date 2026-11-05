"""Source-bound revalidation of the ready seven-scope candidate proof bridge."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


class CandidateProofBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('candidate_proof_bridges', HERE / 'candidate-proof-bridges.py')
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        selected = json.loads((HERE / 'knowledge/candidate-proof-bridges-current.json').read_bytes())
        cls.context = json.loads(Path(selected['context']['path']).read_bytes())
        cls.report = cls.tool.checked(Path('F:/PhoneExit Resources/Vampir'), selected['proof'], 'candidate-proof-bridges-v1')

    def test_complete_seven_scopes_and_completed_projection_barrier(self):
        value = self.tool.validate_saved(self.context, self.report)
        self.assertEqual(len(value['scopes']), 7)
        self.assertTrue(value['projection_barrier']['owner_barrier_completed'])
        self.assertFalse(value['runtime_admitted'])
        self.assertFalse(value['legacy_check_reports_issued'])
        self.assertEqual(value['target_native_executions'], 0)

    def test_changed_source_and_missing_scope_rejected(self):
        for field in ('source_sha256', 'scopes'):
            value = copy.deepcopy(self.report)
            value[field] = '0' * 64 if field == 'source_sha256' else {}
            with self.assertRaisesRegex(ValueError, 'scope differs'):
                self.tool.validate_saved(self.context, value)

    def test_incomplete_owner_barrier_rejected(self):
        value = copy.deepcopy(self.report)
        value['projection_barrier']['owner_barrier_completed'] = False
        with self.assertRaisesRegex(ValueError, 'owner barrier'):
            self.tool.validate_saved(self.context, value)

    def test_damaged_dependency_or_producer_rejected(self):
        value = copy.deepcopy(self.report)
        value['files'][str(HERE / 'candidate-proof-bridges.py')] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'input changed'):
            self.tool.validate_saved(self.context, value)
        value = copy.deepcopy(self.report)
        value['producer']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'producer changed'):
            self.tool.validate_saved(self.context, value)
