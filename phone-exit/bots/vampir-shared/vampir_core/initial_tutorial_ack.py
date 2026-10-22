"""One explicit server acknowledgement; never infers an active UI or autoquest.

The eligibility filter is a local diagnostic policy for the observed initial
1001 record. It does not reproduce the client's unknown cached row +0x50.
"""
import math

from .tutorial_update import decode_tutorial_update
from .tutorial_result import decode_tutorial_result
from .world_move_start import SOURCE_SHA256


class InitialTutorialAck:
    def __init__(self, outbound, *, source_sha256, timeout=10, snapshot_max_age=10):
        if source_sha256 != SOURCE_SHA256:
            raise ValueError('Unsupported initial tutorial source')
        for value in (timeout, snapshot_max_age):
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 30:
                raise ValueError('Invalid initial tutorial time budget')
        self._outbound = outbound
        self._source = source_sha256
        self._timeout = timeout
        self._snapshot_max_age = snapshot_max_age
        self._snapshot_time = self._last_time = self._deadline = self._frame = None
        self.state = 'waiting_snapshot'
        self.result_code = None
        self.unmatched_results = 0

    def __repr__(self):
        return f'InitialTutorialAck(state={self.state!r}, code={self.result_code!r})'

    def _clock(self, now):
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
            raise ValueError('Invalid initial tutorial clock')
        if self._last_time is not None and now < self._last_time:
            raise ValueError('Initial tutorial clock moved backwards')
        self._last_time = now

    def receive(self, packet_id, body, *, now):
        self._clock(now)
        if packet_id == 9905:
            update = decode_tutorial_update(body, source_sha256=self._source,
                max_records=4096, max_payload_size=65536)
            if self.state not in ('waiting_snapshot', 'eligible'):
                return
            rows = [row for row in update.records if row.raw08 == 1001]
            eligible = (not update.flag and len(rows) == 1 and rows[0].state == 1
                        and rows[0].raw0c in (0, 1) and rows[0].raw10 == 0)
            self.state = 'eligible' if eligible else 'waiting_snapshot'
            self._snapshot_time = now if eligible else None
        elif packet_id == 9904:
            result = decode_tutorial_result(body, source_sha256=self._source)
            if (self.state != 'sent' or result.record.raw08 != 1001
                    or result.record.raw0c != 2):
                self.unmatched_results = min(self.unmatched_results + 1, 65535)
                return
            self.result_code = result.code
            self.state = 'accepted' if result.code == 0 else 'rejected'
            self._deadline = None

    def queue(self, *, now):
        self._clock(now)
        if (self.state != 'eligible' or self._snapshot_time is None
                or now - self._snapshot_time > self._snapshot_max_age):
            raise RuntimeError('Fresh initial tutorial snapshot is unavailable')
        # Consume the attempt even if the queue refuses it. No implicit retry.
        self.state = 'not_queued'
        self._snapshot_time = None
        self._frame = self._outbound.queue_initial_tutorial_ack(source_sha256=self._source)
        self.state = 'queued'
        self._deadline = now + self._timeout

    def frame_sent(self, frame):
        if self.state == 'queued' and frame is self._frame:
            self.state = 'sent'
            self._frame = None

    def expire(self, *, now):
        self._clock(now)
        if (self.state == 'eligible'
                and now - self._snapshot_time > self._snapshot_max_age):
            self.state = 'waiting_snapshot'
            self._snapshot_time = None
        if self.state in ('queued', 'sent') and now >= self._deadline:
            self.state = 'unknown'
            self._deadline = self._frame = None
            return True
        return False

    def close(self):
        if self.state in ('queued', 'sent'):
            self.state = 'unknown'
        elif self.state in ('waiting_snapshot', 'eligible'):
            self.state = 'closed'
        self._snapshot_time = self._deadline = self._frame = None
