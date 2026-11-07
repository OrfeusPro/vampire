"""Check exact current Time replay evidence through the normal update gate."""
import copy
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


class QuestTimeCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = spec_from_file_location('verify_quest_time_current', HERE / 'verify-quest-time-current.py')
        cls.tool = module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.pointer = cls.tool.verify()
        cls.report = json.loads(Path(cls.pointer['report']).read_bytes())
        index = cls.tool.load('knowledge-index').api()
        cls.context, cls.rows, cls.selected = cls.tool.definition(index, cls.tool.ROOT, cls.tool.CONTEXT)

    def test_selected_rows_come_from_exact_named_catalog(self):
        self.assertEqual([(row['task_id'], row['index'], row['seconds']) for row in self.rows],
                         [(110110010, 0, .1), (110110020, 1, .1),
                          (110110035, 3, .1), (110110100, 9, .1)])
        self.tool.validate(self.report, self.selected, self.context, self.rows)

    def test_changed_task_index_cannot_reuse_proof(self):
        rows = copy.deepcopy(self.rows)
        rows[0]['index'] = 2
        with self.assertRaises(ValueError):
            self.tool.validate(self.report, self.selected, self.context, rows)

    def test_live_action_cannot_be_inferred_from_replay(self):
        for field in ('live_step_verified', 'actor_vector_verified', 'runtime_admitted'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.tool.validate(dict(self.report, **{field: True}), self.selected, self.context, self.rows)

    def test_cached_proof_reuses_validated_inputs_without_execution(self):
        sys.path.insert(0, str(HERE.parents[2] / '.tools/vampir-analysis'))
        from unicorn import Uc
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected child process')), \
                patch.object(Uc, 'emu_start', side_effect=AssertionError('unexpected native replay')):
            result = self.tool.verify()
        self.assertTrue(result['reused'])
        self.assertEqual(result['sha256'], self.pointer['sha256'])


if __name__ == '__main__':
    unittest.main()
