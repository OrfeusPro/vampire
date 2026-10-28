"""Current default native Ping clock, bound to a successful fresh lobby reply.

Evidence: HEADLESS-RELEASE-CLOCK.md and HEADLESS-RELEASE-BOOTSTRAP.md.
This does not implement periodic scheduling or the full client clock lifecycle.
"""
from dataclasses import dataclass

from .lobby_packets import LobbyVersionResultBody
from .ping import PingPayload
from .runtime_admission import permits

SOURCE_SHA256 = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
INITIAL_PING_SOURCE_SHA256 = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
# Current clock/handler and producer checked separately; periodic/world guards stay separate.
LATEST_PING_SOURCE_SHA256 = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
INITIAL_PING_SOURCES = frozenset((SOURCE_SHA256, INITIAL_PING_SOURCE_SHA256, LATEST_PING_SOURCE_SHA256))


@dataclass(frozen=True, slots=True)
class LobbyPingClock:
    offset_minutes: int

    def __post_init__(self):
        if type(self.offset_minutes) is not int or not -32768 <= self.offset_minutes <= 32767:
            raise ValueError('Expected signed short minute offset')

    @classmethod
    def from_version_result(cls, response, *, source_sha256):
        if source_sha256 not in INITIAL_PING_SOURCES and not permits(source_sha256,'lobby-ping-clock-v1'):
            raise ValueError('Ping clock is not verified for this client source')
        if not isinstance(response, LobbyVersionResultBody):
            raise TypeError('Expected current lobby VersionResult')
        if response.result_code != 0 or response.flag_14:
            raise ValueError('Successful supported lobby Version context required')
        raw = response.raw_38
        return cls(raw if raw < 32768 else raw - 65536)

    def initial_ping(self, *, utc_millis):
        if type(utc_millis) is not int or not 0 <= utc_millis <= 253402300799999:
            raise ValueError('Expected UTC Unix milliseconds in calendar range')
        ticks = (utc_millis + self.offset_minutes * 60000) * 10000
        # Native conversion is signed ticks -> double * 0.0001 -> truncation.
        value = int(float(ticks) * 0.0001)
        if not 5000 < value < 1 << 63:
            raise ValueError('Initial Ping must satisfy native elapsed-time gate')
        return PingPayload(value, value)  # The first producer invocation has last=0.
