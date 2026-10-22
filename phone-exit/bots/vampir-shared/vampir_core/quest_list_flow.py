"""One explicit reset-field diagnostic read, not an inferred game UI lifecycle."""
import math

from .quest_list import decode_quest_list_result
from .world_move_start import SOURCE_SHA256


class QuestListRead:
    def __init__(self, outbound, *, source_sha256, timeout):
        if source_sha256 != SOURCE_SHA256:
            raise ValueError('Unsupported quest list source')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError('Invalid quest list timeout')
        self._outbound, self._source, self._timeout = outbound, source_sha256, timeout
        self._last_time = self._deadline = self._frame = None
        self.state = 'waiting_entry'
        self.result_code = None
        self.response = None
        self.unmatched_results = 0
        self.decode_error = None
        self.decode_body_size = None

    def __repr__(self): return f'QuestListRead(state={self.state!r}, data=<redacted>)'

    def _clock(self, now):
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
            raise ValueError('Invalid quest list clock')
        if self._last_time is not None and now < self._last_time:
            raise ValueError('Quest list clock moved backwards')
        self._last_time = now

    def queue(self, *, now):
        self._clock(now)
        if self.state != 'waiting_entry':
            raise RuntimeError('Quest list attempt already consumed')
        self.state = 'not_queued'
        self._frame = self._outbound.queue_quest_list_read(source_sha256=self._source)
        self.state = 'queued'
        self._deadline = now + self._timeout

    def frame_sent(self, frame):
        if self.state == 'queued' and frame is self._frame:
            self.state, self._frame = 'sent', None

    def receive(self, body, *, now):
        self._clock(now)
        try:
            value = decode_quest_list_result(body, source_sha256=self._source,
                max_collection_items=256, max_total_items=2048, max_payload_size=262144)
        except (ValueError, BufferError) as error:
            # Decoder messages are local constants, never interpolated bodies.
            self.decode_error = str(error)
            self.decode_body_size = len(body)
            raise
        # No verified transaction ID. One outstanding same-connection request,
        # matching raw type, after full local send: diagnostic correlation only.
        if self.state != 'sent' or value.raw14 != 0:
            self.unmatched_results = min(self.unmatched_results + 1, 65535)
            return
        self.result_code = value.code
        self.response = value
        self.state = 'received' if value.code == 0 else 'rejected'
        self._deadline = None

    def expire(self, *, now):
        self._clock(now)
        if self.state in ('queued', 'sent') and now >= self._deadline:
            self.state, self._deadline, self._frame = 'unknown', None, None
            return True
        return False

    def close(self):
        if self.state in ('queued', 'sent'): self.state = 'unknown'
        elif self.state == 'waiting_entry': self.state = 'closed'
        self._deadline = self._frame = None
        self.response = None
