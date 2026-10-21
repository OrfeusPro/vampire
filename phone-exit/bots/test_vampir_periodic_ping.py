"""Source-bound scheduler/queue state; no sockets or game operations."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.heartbeat import PeriodicPing, PingRecoveryRequired
from vampir_core.outbound import OutboundFrames
from vampir_core.session_clock import LobbyPingClock, SOURCE_SHA256
from test_vampir_selection_flow import request_fields


class PeriodicPingTests(unittest.TestCase):
    def setUp(self):
        self.utc=1792632542863
        clock=LobbyPingClock(540)
        self.initial=clock.initial_ping(utc_millis=self.utc)
        self.ping=PeriodicPing(clock,self.initial,source_sha256=SOURCE_SHA256)
        self.out=OutboundFrames(key_bits=7,sequence=10,max_queued_bytes=4096,max_queued_frames=8)

    def test_native_threshold_payload_delta_and_current_key_sequence(self):
        self.assertFalse(self.ping.queue_due(self.out,utc_millis=self.utc+5000,ready=True))
        self.assertTrue(self.ping.queue_due(self.out,utc_millis=self.utc+5001,ready=True))
        self.assertEqual(request_fields(self.out.pop_frame(),7),
            (16,10,struct.pack('<QQ',self.initial.first_bits+5001,5001)))
        self.assertFalse(self.ping.queue_due(self.out,utc_millis=self.utc+5002,ready=True))

    def test_queue_failure_does_not_commit_clock_or_counter(self):
        self.out.close()
        with self.assertRaises(RuntimeError):self.ping.queue_due(self.out,utc_millis=self.utc+5001,ready=True)
        self.assertEqual((self.ping.last,self.ping.outstanding,self.ping.queued_count),(self.initial.first_bits,1,1))

    def test_six_unanswered_pings_require_recovery_without_seventh_frame(self):
        for i in range(1,6):self.assertTrue(self.ping.queue_due(self.out,utc_millis=self.utc+i*5001,ready=True))
        with self.assertRaises(PingRecoveryRequired):self.ping.queue_due(self.out,utc_millis=self.utc+6*5001,ready=True)
        self.assertEqual(self.out.queued_frames,5)
        self.assertEqual(self.ping.outstanding,6)

    def test_any_complete_result_resets_counter_as_current_handler(self):
        for code,value in ((0,0),(16,2**64-1),(0xffffffff,1)):
            self.ping.receive_result(struct.pack('<IQ',code,value))
            self.assertEqual(self.ping.outstanding,0)
        self.assertEqual(self.ping.response_count,3)
        for body in (bytes(11),bytes(13),bytearray(12)):
            with self.assertRaises(ValueError):self.ping.receive_result(body)
        self.assertEqual(self.ping.response_count,3)

    def test_readiness_backward_clock_and_close_do_not_emit_frames(self):
        self.assertFalse(self.ping.queue_due(self.out,utc_millis=self.utc+6000,ready=False))
        self.assertFalse(self.ping.queue_due(self.out,utc_millis=self.utc-5000,ready=True))
        self.assertEqual(self.out.queued_frames,0)
        self.ping.close()
        with self.assertRaises(RuntimeError):self.ping.queue_due(self.out,utc_millis=self.utc+6000,ready=True)
        self.assertEqual(self.ping.last,0)


if __name__=='__main__':unittest.main()
