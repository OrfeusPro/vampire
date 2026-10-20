"""Actual whole ID206 read-to-handler state transition and decoded handoffs."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.world_move_finish_result import decode_world_move_finish_result


class WorldMoveFinishPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-world-move-finish-pipeline.py'
        spec=importlib.util.spec_from_file_location('world_pipeline_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/world-move-finish-pipeline-replay.json').read_text('utf-8'))

    def test_native_pipeline_reproduces(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(len(self.report['cases']),7)
        self.assertFalse(self.report['network_ready'])

    def test_decoder_fields_match_actual_handler_writes(self):
        for case in self.report['cases']:
            decoded=decode_world_move_finish_result(bytes.fromhex(case['decoded']['payload_hex']),
                max_payload_size=4096,max_collection_items=32)
            accepted=decoded.result_code==0 or (decoded.result_code==0x1197 and case['gate_state']==0)
            self.assertEqual(case['state']['status30'],6 if accepted else 1)
            self.assertEqual(case['state']['refs'],2)
            calls=[e for e in case['events'] if e['action']=='native_virtual78']
            self.assertEqual(len(calls),int(accepted))
            if accepted:
                self.assertEqual(case['state']['raw40'],decoded.data.at(0x20))
                self.assertEqual(case['state']['player1f8'],decoded.data.at(0x20))
                self.assertEqual(calls[0]['raw_type'],decoded.data.at(0x29))
                self.assertEqual(calls[0]['raw119'],decoded.data.at(0x119))

    def test_nonempty_nested_world_item_reaches_handler_boundary(self):
        case=self.report['cases'][-1]
        calls=[e for e in case['events'] if e['action']=='world_item_capture']
        self.assertEqual(calls,[dict(action='world_item_capture',enum=5,raw10=18,raw_c=17)])
        self.assertEqual(case['decoded']['text'],'Ж界🙂')
        writes=[e for e in case['events'] if e['action']=='native_status_set']
        self.assertEqual([(e['old'],e['value']) for e in writes],[(1,6)])


if __name__=='__main__':unittest.main()
