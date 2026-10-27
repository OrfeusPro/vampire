"""Current Ping producer policy; single-owner queue, no reconnect or game IO."""
from .ping import PingPayload, PingResultPayload
from .session_clock import LobbyPingClock, SOURCE_SHA256, INITIAL_PING_SOURCE_SHA256, LATEST_PING_SOURCE_SHA256

# Reviewed producer and receiver, plus bounded live observation. Initial Ping
# support alone must not expand this set on a future client update.
HEARTBEAT_SOURCES=frozenset((SOURCE_SHA256,INITIAL_PING_SOURCE_SHA256,LATEST_PING_SOURCE_SHA256))


class PingRecoveryRequired(TimeoutError):
    """Owner must close/recover explicitly; do not replay queued game actions."""


class PeriodicPing:
    def __init__(self,clock,initial_ping,*,source_sha256):
        if source_sha256 not in HEARTBEAT_SOURCES:raise ValueError('Unsupported heartbeat source')
        if not isinstance(clock,LobbyPingClock) or not isinstance(initial_ping,PingPayload):
            raise TypeError('Verified clock and queued initial Ping required')
        if initial_ping.first_bits!=initial_ping.second_bits or not 5000<initial_ping.first_bits<2**63:
            raise ValueError('Expected initial native Ping with last=0')
        self.clock=clock
        self.last=initial_ping.first_bits
        self.outstanding=1
        self.queued_count=1
        self.response_count=0
        self.closed=False

    def __repr__(self):return f'PeriodicPing(outstanding={self.outstanding}, clock=<redacted>)'

    def queue_due(self,outbound,*,utc_millis,ready):
        """Owner supplies readiness; commit state only after queue accepts frame.

        Recovery is surfaced to the owner instead of executing native engine recovery.
        Clock resync and the native diagnostic override are deliberately not emulated.
        """
        if self.closed:raise RuntimeError('Heartbeat is closed')
        if type(ready) is not bool:raise ValueError('Explicit heartbeat readiness required')
        if not ready:return False
        current=self.clock.initial_ping(utc_millis=utc_millis).first_bits
        delta=current-self.last
        if delta<=5000:return False
        if self.outstanding>=6:raise PingRecoveryRequired('Ping responses missing')
        outbound.queue_ping(PingPayload(current,delta))
        self.last=current
        self.outstanding+=1
        self.queued_count+=1
        return True

    def receive_result(self,body):
        if self.closed:raise RuntimeError('Heartbeat is closed')
        if type(body) is not bytes:raise ValueError('Immutable PingResult body required')
        result=PingResultPayload.decode(body)
        # Current handler does not branch on either wire field before reset.
        self.outstanding=0
        self.response_count+=1
        return result

    def close(self):
        self.closed=True
        self.last=0
        self.outstanding=0
