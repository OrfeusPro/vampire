"""Native finish guard and portable empty-body frame parity."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.send_frame import encode_world_move_finish_frame_b


class WorldMoveFinishSendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-world-move-finish-send.py'
        spec=importlib.util.spec_from_file_location('finish_send_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/world-move-finish-send-replay.json').read_text('utf-8'))

    def test_native_execution_reproduces(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['matrix']),256)

    def test_guard_only_accepts_two_three_four_and_blocks_repeat(self):
        for case in self.report['matrix']:
            accepted=case['status'] in (2,3,4)
            self.assertEqual(case['returned'],int(accepted))
            self.assertEqual(case['state']['status30'],5 if accepted else case['status'])
            self.assertEqual(len([e for e in case['events'] if e['action']=='finish_packet_capture']),int(accepted))
            if accepted:
                self.assertEqual(case['repeat_return'],0)
                self.assertEqual(case['repeat_events'],[])
            else:
                self.assertEqual(case['state']['raw150'],23)
                self.assertEqual(case['state']['raw154_hex'],struct.pack('<f',9.5).hex())
                self.assertEqual(case['state']['raw158'],41)

    def test_pending_prepares_state_without_sending_and_config_is_clamped(self):
        for case in self.report['extra']:
            if case['pending']:
                self.assertEqual(case['returned'],0)
                self.assertEqual(case['state']['status30'],3)
                self.assertEqual(case['state']['pending'],1)
                self.assertIn(dict(action='pending_label_capture',raw=37),case['events'])
                self.assertFalse(any(e['action']=='finish_packet_capture' for e in case['events']))
            else:
                expected=struct.pack('<f',max(float(case['config']),self.report['minimum']['value'])).hex()
                self.assertEqual(case['state']['raw154_hex'],expected)
                self.assertEqual((case['state']['raw150'],case['state']['raw158']),(0,1))

    def test_portable_frame_matches_native_writer_crc_xor_queue(self):
        self.assertEqual(len(self.report['frames']),4)
        for case in self.report['frames']:
            f=case['fixture'];frame=encode_world_move_finish_frame_b(f['sequence'],f['key'])
            self.assertEqual(frame.hex(),case['frame_hex'])
            self.assertEqual(len(frame),11)
            self.assertEqual(case['sequence_after'],(f['sequence']+1) & 65535)
            self.assertEqual(case['queue_calls'],1)
            self.assertTrue(case['queue_owns_bytes'])
            self.assertIn(dict(action='packet_name_constructor_fixture',name='PktWorldMoveFinish'),case['events'])
        for value in (-1,65536,True,None):
            with self.assertRaises(ValueError):encode_world_move_finish_frame_b(value,0)


if __name__=='__main__':unittest.main()
