import importlib.util
import json
from pathlib import Path
import unittest


class SelectedPlayerRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-selected-player-record.py'
        spec = importlib.util.spec_from_file_location('selected_record_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/selected-player-record-replay.json').read_text('utf-8'))

    def test_native_pipeline_reproduces(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual(len(self.report['cases']), 20)
        self.assertEqual(self.report['empty_table_return'], 0)
        self.assertFalse(self.report['network_ready'])
        self.assertFalse(self.report['field_semantics_verified'])

    def test_collision_chain_and_unsigned_key(self):
        hits = []
        for case in self.report['cases']:
            self.assertEqual(case['state']['raw10'], case['key'])
            self.assertEqual(bool(case['record_pointer']), case['key'] in case['keys'])
            if case['record_pointer']:
                hits.append(case['key'])
        self.assertEqual(hits, [7, 3, 7, 0xffffffff, 3, 7, 0xffffffff])

    def test_inline_and_dynamic_buckets_agree(self):
        inline = self.report['cases'][10:15]
        dynamic = self.report['cases'][15:20]
        self.assertEqual([c['record_pointer'] for c in inline], [c['record_pointer'] for c in dynamic])
        self.assertEqual([c['state'] for c in inline], [c['state'] for c in dynamic])


if __name__ == '__main__':
    unittest.main()
