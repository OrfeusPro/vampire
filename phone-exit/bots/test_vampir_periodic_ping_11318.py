"""Current source scheduler backed by the whole current producer/result package."""
import unittest
from pathlib import Path
from test_vampir_periodic_ping import PeriodicPingTests
from test_vampir_update_contracts import load
from vampir_core.heartbeat import PeriodicPing
from vampir_core.session_clock import LATEST_PING_SOURCE_SHA256

class CurrentPeriodicPingTests(PeriodicPingTests):
    @classmethod
    def setUpClass(cls):
        cls.proof=load('run-clock-world-batch-11318').run(Path('F:/PhoneExit Resources/Vampir'))[1]
        assert cls.proof['source_sha256']==LATEST_PING_SOURCE_SHA256

    def setUp(self):
        super().setUp()
        self.ping=PeriodicPing(self.ping.clock,self.initial,source_sha256=LATEST_PING_SOURCE_SHA256)

if __name__=='__main__':unittest.main()
