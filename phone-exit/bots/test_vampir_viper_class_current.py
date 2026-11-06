"""Source-bound current class consumers; engine services remain explicit fixtures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'
spec = importlib.util.spec_from_file_location('viper_class_current_tests', HERE / 'verify-viper-class-current.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class ViperClassCurrentTests(unittest.TestCase):
    def test_whole_lookup_selection_and_type_getter_preserve_id_type_and_gate_boundaries(self):
        result = tool.verify()
        report = json.loads(Path(result['report']).read_bytes())
        self.assertEqual(result['native_cases'], 49)
        self.assertEqual(len(report['lookup_cases']), 27)
        self.assertEqual(len(report['selection_cases']), 16)
        self.assertEqual(len(report['type_cases']), 6)
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['runtime_admitted'])
        self.assertFalse(report['loaded_class_table_verified'])
        self.assertFalse(report['complete_viper_payload_verified'])
        selected = [case for case in report['selection_cases'] if case['stored']]
        viper = [case for case in selected if case['kind'] == 1]
        self.assertEqual([case['gender'] for case in viper], [0, 1])
        self.assertTrue(all(case['stored_id'] == 0x80003000 for case in viper))
        self.assertTrue(all(case['stored_id'] != case['kind'] for case in selected))
        duplicate = next(case for case in report['lookup_cases'] if case['count'] == 35 and case['kind'] == 1)
        self.assertEqual(duplicate['expected_slot'], 3)
        self.assertEqual(duplicate['row_id'], 0x80002003)
        self.assertEqual({case['blocker'] for case in report['selection_cases'] if not case['stored']},
            {'disabled', 'busy', 'null_actor', 'wrong_mode', 'not_ready', 'bad_actor_type', 'kind100', 'gender2'})
        self.assertEqual({case['returned'] for case in report['type_cases']}, {0, 1, 3, 5})

    def test_changed_source_binding_is_rejected_instead_of_reusing_old_identity(self):
        context = json.loads(tool.CONTEXT.read_bytes())
        context['source_anchors'][0]['bytes'] = '00' * 16
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'context.json'
            path.write_text(json.dumps(context), 'utf-8')
            with self.assertRaisesRegex(ValueError, 'source binding changed'):
                tool.verify(path)


if __name__ == '__main__':
    unittest.main()
