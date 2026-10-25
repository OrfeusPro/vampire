"""Bounded current source replay and transition policy; no live authentication."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.world_move_start import CURRENT_PROBE_SOURCE
from vampir_core.world_entry_flow import WorldEntryFlow
from vampir_core.heartbeat import PeriodicPing
from vampir_core.session_clock import LobbyPingClock
from test_vampir_world_entry_flow import WorldEntryFlowTests,reserve_body,finish_body
from test_vampir_periodic_ping import PeriodicPingTests
import struct


class CurrentWorldPolicyTests(WorldEntryFlowTests):
    def setUp(self):
        super().setUp()
        self.flow=WorldEntryFlow(self.selection,self.outbound,source_sha256=CURRENT_PROBE_SOURCE,
            timeout=1,max_payload_size=4096)

    def test_current_world_completes_only_after_all_responses(self):
        flow=WorldEntryFlow(self.selection,self.outbound,source_sha256=CURRENT_PROBE_SOURCE,
            timeout=1,max_payload_size=4096,complete_world=True)
        flow.tick(0);flow.receive(202,reserve_body(),now=0.1)
        flow.receive(204,struct.pack('<IIfffBBQ',0,10010,1,2,3,0,0,0),now=0.2)
        self.assertEqual(flow.state,'finish_pending')
        flow.receive(206,finish_body(),now=0.3)
        self.assertEqual(flow.state,'finish_response')
        self.assertEqual(flow.target_position.world_id,10010)


class CurrentHeartbeatTests(PeriodicPingTests):
    def setUp(self):
        super().setUp()
        self.ping=PeriodicPing(LobbyPingClock(540),self.initial,source_sha256=CURRENT_PROBE_SOURCE)


class CurrentNativeTests(unittest.TestCase):
    def test_actual_current_writers_readers_and_receiver(self):
        base=HERE/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('world_native_test',base/'replay-world-entry-11316.py')
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        exports=json.loads((base/'knowledge/native-contexts/world-entry-exports-11316.json').read_text('utf-8'))
        self.assertEqual(m.verify(exports)['cases'],201)
        with self.assertRaisesRegex(ValueError,'export SHA'):
            m.verify({k:'0'*64 for k in exports})


if __name__=='__main__':unittest.main()
