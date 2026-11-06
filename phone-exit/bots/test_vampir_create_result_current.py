"""Current Create Result composition cache, handoff and scope checks."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent / 'resource-tools/vampir'


class CurrentCreateResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('current_create_result', HERE / 'verify-create-result-current.py')
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.path, cls.report, _ = cls.tool.run()

    def test_cached_pass_needs_no_native_execution(self):
        with patch.object(self.tool, 'execute', side_effect=AssertionError('Unexpected native replay')):
            checked = self.tool.verify()
        self.assertTrue(checked['reused'])
        self.assertEqual(checked['sha256'], self.path.parent.name)

    def test_full_record_for_all_codes_and_short_record_rejected(self):
        for code in (0, 58, 0xffffffff):
            rows = [row for row in self.report['cases'] if row['code'] == code]
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(row['accepted'] and row['nested_reader']
                                and row['consumed'] == row['available'] for row in rows))
        self.assertEqual([row['nested_reader'] for row in self.report['failures']], [False, True, True])
        self.assertTrue(all(not row['accepted'] and row['consumed'] <= row['available']
                            for row in self.report['truncated']))
        self.assertEqual(self.report['extra']['available'] - self.report['extra']['consumed'], 1)
        self.assertFalse(self.report['runtime_admitted'])
        self.assertFalse(self.report['network_used'])

    def test_rejects_changed_parent_proof(self):
        context = json.loads(self.tool.CONTEXT.read_bytes())
        context['packet_proof']['sha256'] = '0' * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'context.json'
            path.write_text(json.dumps(context), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'packet proof changed'):
                self.tool.verify_report(self.path, context_path=path)

    def test_content_addressed_report_cannot_drop_retained_input(self):
        changed = copy.deepcopy(self.report)
        inputs = changed['definition']['inputs']
        removed = next(name for name in inputs if name.endswith('character-list-records.json'))
        del inputs[removed]
        audit = self.tool.load('audit-client-release')
        path = audit.save_snapshot(self.tool.ROOT / 'code-clues' / self.tool.RECIPE, changed)
        with self.assertRaisesRegex(ValueError, 'cached proof scope differs'):
            self.tool.verify_report(path)


if __name__ == '__main__':
    unittest.main()
