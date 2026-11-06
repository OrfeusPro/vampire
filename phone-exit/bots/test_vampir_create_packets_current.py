"""Current Create source bindings and explicit outer-result proof boundaries."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent / 'resource-tools/vampir'


class CurrentCreatePacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('current_create_packet_fixture', HERE / 'verify-create-packets-current.py')
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.path, cls.report, reused = cls.tool.run()
        if not reused:
            raise AssertionError('Source proof must be prepared before tooling tests')

    def test_unchanged_reuses_proof_without_native_execution(self):
        with patch.object(self.tool, 'execute', side_effect=AssertionError('Unexpected native replay')):
            path, report, reused = self.tool.run()
        self.assertTrue(reused)
        self.assertEqual(path, self.path)
        self.assertEqual(report, self.report)

    def test_raw_class_unicode_and_failure_handoffs_are_preserved(self):
        self.assertEqual({case['raw_class'] for case in self.report['cases']}, {1, 3, 0xffffffff})
        self.assertTrue(any(case['unicode'] and case['variant'] for case in self.report['cases']))
        self.assertEqual([case['operations'] for case in self.report['failures']], list(range(1, 19)))

    def test_nonzero_result_does_not_skip_required_nested_record(self):
        for case in self.report['result_cases']:
            self.assertEqual(case['accepted'], int(case['header_ok'] and case['record_ok']))
        self.assertEqual(self.report['bindings']['packet_ids'], [103, 104, 109, 110])
        self.assertFalse(self.report['runtime_admitted'])
        self.assertFalse(self.report['network_used'])
        self.assertTrue(any('fixtures' in text for text in self.report['limits']))

    def test_different_writer_role_is_rejected_before_execution(self):
        context = json.loads(self.tool.CONTEXT.read_bytes())
        context['functions']['request_writer'] = '0x1456e8430'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'context.json'
            path.write_text(json.dumps(context), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'roles changed'):
                self.tool.materials(context_path=path)

    def test_cached_proof_cannot_drop_retained_source(self):
        report = copy.deepcopy(self.report)
        source = next(name for name in report['definition']['inputs'] if name.endswith('ProjectRED-Win64-Shipping.exe'))
        del report['definition']['inputs'][source]
        report['negative_tooling_fixture'] = True
        path = self.tool.load('audit-client-release').save_snapshot(self.tool.ROOT / 'code-clues' / self.tool.RECIPE, report)
        with self.assertRaisesRegex(ValueError, 'definition changed'):
            self.tool.verify_report(path)


if __name__ == '__main__':
    unittest.main()
