"""Explicit headless completion policy; no external network or game IO."""
import struct
import unittest

import test_vampir_world_entry_flow as entry_tests
from test_vampir_world_entry_flow import reserve_body, finish_body
from vampir_core.world_entry_flow import WorldEntryFlow
from vampir_core.world_move_start import SOURCE_SHA256
from test_vampir_selection_flow import request_fields


class WorldCompletionFlowTests(unittest.TestCase):
    def setUp(self):
        fixture=entry_tests.WorldEntryFlowTests();fixture.setUp()
        self.outbound=fixture.outbound
        self.flow=WorldEntryFlow(fixture.selection,self.outbound,source_sha256=SOURCE_SHA256,
            timeout=1,max_payload_size=4096,complete_world=True,max_collection_items=64)

    def start(self):
        self.flow.receive(202,reserve_body(),now=0)
        self.outbound.pop_frame()
        self.flow.receive(204,struct.pack('<IIIIIBBQ',0,9,0x3fc00000,0xc0100000,0x80000000,0,0,0),now=.1)

    def test_one_empty_finish_same_sequence_and_server_target_from206(self):
        self.start()
        self.assertEqual(request_fields(self.outbound.pop_frame(),0),(205,11,b''))
        self.assertEqual(self.flow.state,'finish_pending')
        self.flow.receive(206,finish_body(vector=(9,8,7)),now=.2)
        self.assertEqual(self.flow.state,'finish_response')
        self.assertEqual(self.flow.target_position.world_id,9)
        self.assertEqual(self.flow.target_position.vector.finite_values(),(9,8,7))
        self.assertEqual(self.flow.finish_result_code,0)
        self.flow.tick(3)
        self.assertIsNone(self.flow.error)
        self.assertIsNone(self.outbound.pop_frame())
        self.flow.close()
        self.assertIsNone(self.flow.target_position)
        self.assertIsNone(self.flow.finish_response)
        self.assertEqual(self.flow.finish_result_code,0)

    def test_refusal_and_timeout_clear_pending_request_without_retry(self):
        for refusal in (False,True):
            self.setUp();self.start()
            if refusal:self.flow.receive(206,finish_body(16),now=.2)
            else:self.flow.tick(1.1)
            self.assertEqual(self.flow.error,'finish_result_rejected' if refusal else 'world_entry_timeout')
            self.assertIsNone(self.flow.target_position)
            self.assertEqual(self.outbound.queued_frames,0)

    def test_early_duplicate_truncated_and_nonfinite_responses_fail_closed(self):
        for kind in ('early','duplicate','short','nonfinite'):
            self.setUp()
            if kind!='early':self.start()
            if kind=='duplicate':self.flow.receive(206,finish_body(),now=.2)
            body=finish_body(vector=(float('nan'),0,0)) if kind=='nonfinite' else finish_body()
            if kind=='short':body=body[:-1]
            with self.assertRaises(ValueError):self.flow.receive(206,body,now=.3)
            self.assertEqual(self.flow.error,'invalid_world_entry_response')
            self.assertEqual(self.outbound.queued_frames,0)
            self.assertIsNone(self.flow.target_position)

    def test_completion_requires_current_source_and_adequate_budgets(self):
        for kwargs in ({'complete_world':1},{'max_payload_size':80},{'max_collection_items':True},
                {'source_sha256':'c7552efd'},{'max_collection_items':-1}):
            options=dict(source_sha256=SOURCE_SHA256,timeout=1,max_payload_size=4096,complete_world=True)
            options.update(kwargs)
            with self.assertRaises(ValueError):WorldEntryFlow(self.flow.selection,self.outbound,**options)

    def test_start_refusal_or_nonfinite_position_never_sends_finish(self):
        for code,bits in ((16,0),(0,0x7fc00000)):
            self.setUp();self.flow.receive(202,reserve_body(),now=0);self.outbound.pop_frame()
            body=struct.pack('<IIIIIBBQ',code,9,bits,0,0,0,0,0)
            if code:self.flow.receive(204,body,now=.1)
            else:
                with self.assertRaises(ValueError):self.flow.receive(204,body,now=.1)
            self.assertFalse(self.flow.finish_sent)
            self.assertEqual(self.outbound.queued_frames,0)


if __name__=='__main__':unittest.main()
