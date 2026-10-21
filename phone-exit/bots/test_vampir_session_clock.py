import struct
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))

from vampir_core.lobby_packets import decode_lobby_version_result
from vampir_core.session_clock import LobbyPingClock, SOURCE_SHA256


class SessionClockTests(unittest.TestCase):
    def clock(self, offset, *, code=0, flag=0, source=SOURCE_SHA256):
        reply = decode_lobby_version_result(struct.pack('<IBQQH', code, flag,
            123, 987654321, offset & 65535))
        return LobbyPingClock.from_version_result(reply, source_sha256=source)

    def test_reference_first_ping_uses_utc_and_lobby_minutes(self):
        ping = self.clock(540).initial_ping(utc_millis=1792600142863)
        self.assertEqual((ping.first_bits, ping.second_bits), (1792632542863,) * 2)

    def test_signed_minutes_and_native_double_conversion(self):
        for offset in (-32768, -180, 0, 540, 32767):
            clock = self.clock(offset)
            self.assertEqual(clock.offset_minutes, offset)
            utc = 1792600142863
            expected = int(float((utc + offset * 60000) * 10000) * 0.0001)
            self.assertEqual(clock.initial_ping(utc_millis=utc).first_bits, expected)

    def test_unverified_or_rejected_lobby_context_is_refused(self):
        for kwargs in (dict(code=16), dict(flag=1), dict(source='old-source')):
            with self.assertRaises(ValueError): self.clock(540, **kwargs)
        with self.assertRaises(TypeError):
            LobbyPingClock.from_version_result(None, source_sha256=SOURCE_SHA256)
        for value in (True, -1, 5000, 253402300800000):
            with self.assertRaises(ValueError): self.clock(0).initial_ping(utc_millis=value)


if __name__ == '__main__': unittest.main()
