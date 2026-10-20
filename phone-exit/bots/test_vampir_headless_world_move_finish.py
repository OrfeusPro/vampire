"""Native ID206 handler and source-bound selection lifecycle transition."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest

HERE=Path(__file__).parent


class WorldMoveFinishTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-world-move-finish.py'
        spec=importlib.util.spec_from_file_location('world_move_finish_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/world-move-finish-replay.json').read_text('utf-8'))

    def test_native_execution_reproduces(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(len(self.report['cases']),10)
        self.assertFalse(self.report['network_ready'])
        self.assertFalse(self.report['wire_reader_executed'])

    def test_packet_and_service_bindings(self):
        self.assertEqual(self.report['packet_id'],206)
        self.assertEqual(bytes.fromhex(self.report['id_leaf']['bytes']),b'\xb8'+struct.pack('<I',206)+b'\xc3')
        self.assertEqual(bytes.fromhex(self.report['name_reference']['literal_hex']),b'PktWorldMoveFinishResult\0')
        self.assertEqual([r['target'] for r in self.report['table_bindings']],
            [self.tool.HANDLER,self.tool.VIRTUAL78])
        self.assertEqual(len(self.report['registration']),3)

    def test_accepted_result_passes_packet_fields_and_changes_state(self):
        for case in self.report['cases']:
            accepted=case['player_raw8_nonzero'] and (case['code']==0 or (case['code']==0x1197 and case['gate_state']==0))
            calls=[e for e in case['events'] if e['action']=='native_virtual78']
            self.assertEqual(len(calls),int(accepted))
            state=case['state'];self.assertEqual(state['refs'],2)
            self.assertEqual(state['status30'],6 if accepted else 1)
            if accepted:
                self.assertEqual(calls[0],dict(action='native_virtual78',raw20=case['raw20'],raw_type=case['raw_type'],raw119=case['raw119']))
                self.assertEqual(state['raw38'],0x123456789abcdef)
                self.assertEqual(state['raw40'],case['raw20'])
                self.assertEqual(state['raw48'],0x89abcdef)
                self.assertEqual(state['raw50'],7)
                self.assertEqual(state['raw58'],case['raw_type'])
                self.assertEqual(state['rawf1'],1)
                self.assertEqual(state['player1f8'],case['raw20'])
                self.assertIn(dict(action='world_delegate_capture',raw20=case['raw20']),case['events'])
                writes=[e for e in case['events'] if e['action']=='native_status_set']
                self.assertEqual([(e['old'],e['value']) for e in writes],[(1,6)])

    def test_gate_and_raw8_guard_keep_rejection_distinct(self):
        for case in self.report['cases']:
            gates=[e for e in case['events'] if e['action']=='native_gate']
            self.assertEqual(len(gates),int(case['player_raw8_nonzero']))
            if gates:self.assertEqual(gates[0]['packet_id'],206)
            rejected=case['player_raw8_nonzero'] and (case['code']==1 or (case['code']==0x1197 and case['gate_state']==1))
            self.assertEqual(any(e['action']=='result_rejected_capture' for e in case['events']),rejected)


if __name__=='__main__':unittest.main()
