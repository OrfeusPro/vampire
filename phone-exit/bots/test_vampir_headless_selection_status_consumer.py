"""Native consumer gate distinguishes selection response from later lifecycle."""
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).parent


class SelectionStatusConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-selection-status-consumer.py'
        spec=importlib.util.spec_from_file_location('status_consumer_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/selection-status-consumer-replay.json').read_text('utf-8'))

    def test_native_pipeline_reproduces(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])

    def test_unsigned_byte_gate_all_values(self):
        self.assertEqual([c['status'] for c in self.report['matrix']],list(range(256)))
        for case in self.report['matrix']:
            sends=[e for e in case['events'] if e['action']=='request_handoff_capture']
            self.assertEqual(len(sends),int(case['status']>=6))
            if sends:
                self.assertEqual(sends[0]['kind'],319)
                self.assertEqual(sends[0]['raw10'],0x89abcdef)
                self.assertEqual(sends[0]['packet_flag_a'],1)
                self.assertEqual(sends[0]['timeout_hex'],'00000000')

    def test_clear_preserves_status_initialize_sets_seven(self):
        self.assertEqual(len(self.report['leaves']),5)
        for case in self.report['leaves']:
            self.assertEqual(case['after_clear'],case['prior'])
            self.assertEqual(case['after_initialize'],7)

    def test_response_and_explicit_lifecycle_are_separate(self):
        self.assertEqual(len(self.report['transitions']),3)
        for case in self.report['transitions']:
            self.assertEqual(case['after_response'],1)
            self.assertEqual(case['before_events'],[])
            self.assertEqual(case['after_lifecycle'],6)
            setters=[e for e in case['lifecycle_events'] if e['action']=='native_status_set']
            self.assertEqual([(e['old'],e['value']) for e in setters],[(1,6)])
            self.assertEqual(case['after_events'][0]['action'],'request_handoff_capture')
            self.assertEqual(case['after_events'][0]['raw10'],case['raw'])
            self.assertEqual(case['depth'],17)
            self.assertEqual(case['flags'],0x1122334455667688)


if __name__=='__main__':unittest.main()
