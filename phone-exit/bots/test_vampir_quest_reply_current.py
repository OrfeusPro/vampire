"""Check the current 1811 proof, legacy codec parity and warm cache boundary."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.quest_update_result import CURRENT_SOURCE_SHA256, decode_quest_update_result


class QuestReplyCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = HERE / 'resource-tools/vampir/verify-quest-reply-current.py'
        spec = importlib.util.spec_from_file_location('quest_reply_current_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.cases = cls.tool.load('quest-reply-cases-v1')
        cls.pointer = cls.tool.verify()
        cls.report = json.loads(Path(cls.pointer['report']).read_bytes())

    def test_current_wire_projection_matches_existing_portable_layout(self):
        wire = self.report['result']['wire']
        self.assertEqual(len(wire), 936)
        self.assertEqual(sum(row['accepted'] for row in wire), 900)
        for case in wire:
            if not case['accepted']:
                continue
            value = decode_quest_update_result(self.cases.WIRE.pack(*case['input']),
                                               source_sha256=CURRENT_SOURCE_SHA256)
            self.assertEqual([value.result_code, value.quest_id, value.state, *vars_from_progress(value.progress)],
                             case['decoded'])
        with self.assertRaisesRegex(ValueError, 'Unsupported'):
            decode_quest_update_result(self.cases.WIRE.pack(*self.cases.SAMPLE),
                                       source_sha256=self.report['source_sha256'])

    def test_gate_application_differs_from_action_success(self):
        results = self.report['result']['applications']
        self.assertEqual(len(results), 192)
        special_result = [row for row in results if row['code'] == 0x1197]
        self.assertEqual(sum(row['applies'] for row in special_result), 24)
        for row in special_result:
            self.assertEqual(row['applies'], not row['special'])
            self.assertEqual('error' in row['calls'], not row['special'])
        self.assertFalse(self.report['runtime_admitted'])
        self.assertFalse(self.report['applied_to_local_task'])
        self.assertFalse(self.report['action_confirmed'])

    def test_warm_cache_does_not_enter_native_runner_or_spawn(self):
        index = self.tool.load('knowledge-index').api()
        original = index.extension

        def extension(name):
            return self.cases if name == 'quest-reply-cases-v1' else original(name)

        index.extension = extension
        legacy_load = self.tool.load
        loader = legacy_load('knowledge-index')
        loader.api = lambda: index
        with patch.object(self.cases, 'run', side_effect=AssertionError('native replay')), \
                patch.object(self.tool, 'load', side_effect=lambda name: loader if name == 'knowledge-index' else legacy_load(name)), \
                patch('subprocess.Popen', side_effect=AssertionError('process spawn')):
            self.assertEqual(self.tool.verify(), dict(self.pointer, reused=True))

    def test_forged_wire_gate_and_admission_are_rejected(self):
        definition = self.report['definition']
        forged = copy.deepcopy(self.report)
        forged['result']['wire'][0]['decoded'][2] = 7
        with self.assertRaisesRegex(ValueError, 'wire matrix'):
            self.tool.validate(self.cases, forged, definition)
        forged = copy.deepcopy(self.report)
        forged['result']['applications'][0]['calls'].clear()
        with self.assertRaisesRegex(ValueError, 'application matrix'):
            self.tool.validate(self.cases, forged, definition)
        forged = dict(self.report, action_confirmed=True)
        with self.assertRaisesRegex(ValueError, 'scope differs'):
            self.tool.validate(self.cases, forged, definition)

    def test_cached_receipt_checks_inputs_again_before_return(self):
        with patch.object(self.tool, 'barrier', side_effect=[None, ValueError('late input mutation')]) as guard:
            with self.assertRaisesRegex(ValueError, 'late input mutation'):
                self.tool.verify()
        self.assertEqual(guard.call_count, 2)


def vars_from_progress(value):
    return value.raw08, value.raw10, value.raw18


if __name__ == '__main__':
    unittest.main()
