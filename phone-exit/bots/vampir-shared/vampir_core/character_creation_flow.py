"""One explicit creation attempt on an accepted empty list, never replayed."""
import math

from .character_create import encode_character_create
from .character_create_result import decode_character_create_result, character_creation_outcome, SOURCE_SHA256
from .selection_flow import SelectionState


class CharacterCreationFlow:
    def __init__(self, outbound, *, source_sha256, timeout):
        if source_sha256 != SOURCE_SHA256:
            raise ValueError('Unsupported creation source')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError('Invalid creation timeout')
        self._outbound, self._source, self._timeout = outbound, source_sha256, timeout
        self.state = 'waiting_entry'
        self.outcome = None
        self.result_code = None
        self.unmatched_results = 0
        self._deadline = self._last_time = self._frame = self._name = None

    def __repr__(self): return f'CharacterCreationFlow(state={self.state!r}, data=<redacted>)'

    @property
    def deadline(self): return self._deadline

    def _clock(self, now):
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
            raise ValueError('Invalid creation clock')
        if self._last_time is not None and now < self._last_time:
            raise ValueError('Creation clock moved backwards')
        self._last_time = now

    def queue(self, payload, selection, *, now):
        self._clock(now)
        if self.state != 'waiting_entry': raise RuntimeError('Creation attempt already consumed')
        if (selection.state != SelectionState.LIST_AVAILABLE or selection.result_code != 0
                or selection.characters is None or selection.characters.result_code != 0
                or selection.characters.records):
            raise RuntimeError('Creation requires an accepted empty character list')
        encode_character_create(payload, source_sha256=self._source)
        if not payload.name or payload.raw_class == 0:
            raise ValueError('Creation requires explicit class and nickname')
        deadline = now + self._timeout
        if not math.isfinite(deadline): raise ValueError('Creation deadline overflow')
        self.state = 'not_queued'
        self._frame = self._outbound.queue_character_create(payload, source_sha256=self._source)
        self._name, self._deadline, self.state = payload.name, deadline, 'queued'

    def frame_sent(self, frame):
        if self.state == 'queued' and frame is self._frame:
            self.state, self._frame = 'sent', None

    def receive(self, body, *, now):
        self.expire(now=now)
        if self.state != 'sent':
            self.unmatched_results = min(65535, self.unmatched_results + 1)
            return
        try:
            result = decode_character_create_result(body, source_sha256=self._source,
                max_payload_size=1048576, max_extension_items=4096)
            outcome = character_creation_outcome(result, source_sha256=self._source, requested_name=self._name)
        except (ValueError, BufferError):
            self.state, self._deadline, self._frame = 'unknown', None, None
            raise
        self.outcome, self.result_code = outcome, result.result_code
        self.state, self._deadline = outcome.status, None

    def expire(self, *, now):
        self._clock(now)
        if self.state in ('queued', 'sent') and now >= self._deadline:
            self.state, self._deadline, self._frame = 'unknown', None, None
            return True
        return False

    def close(self):
        if self.state in ('queued', 'sent'): self.state = 'unknown'
        elif self.state == 'waiting_entry': self.state = 'closed'
        self._deadline = self._frame = self._name = None
