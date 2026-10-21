"""One connection's bounded character-list/selection request lifecycle.

Local orchestration over verified codecs, not a reimplementation of the engine
world loader. A session owner must establish the list-entry policy, dispatch
complete incoming bodies, drive deadlines and close this flow on disconnect.
No LoginResult-to-entry shortcut, automatic retry, world/position claim or IO.
"""
from dataclasses import dataclass
from enum import Enum
import math

from .character_list import decode_character_list, preferred_character_index
from .character_select import CharacterSelectPayload
from .character_select_result import decode_character_select_result
from .outbound import OutboundFrames


class SelectionState(str, Enum):
    WAITING_ENTRY = 'waiting_entry'
    LIST_PENDING = 'list_pending'
    LIST_AVAILABLE = 'list_available'
    SELECT_PENDING = 'select_pending'
    SELECT_RESPONSE = 'select_response'
    FAILED = 'failed'
    CLOSED = 'closed'


@dataclass(frozen=True, slots=True)
class SelectionLimits:
    max_payload_size: int
    max_characters: int
    max_collection_items: int
    request_timeout: float

    def __post_init__(self):
        for value, lo, hi in ((self.max_payload_size, 203, 0xffffff),
                              (self.max_characters, 0, 65535),
                              (self.max_collection_items, 0, 65535)):
            if type(value) is not int or not lo <= value <= hi:
                raise ValueError('Invalid selection resource limit')
        if type(self.request_timeout) not in (int, float) or not math.isfinite(self.request_timeout) or self.request_timeout <= 0:
            raise ValueError('Selection timeout must be positive and finite')


class CharacterSelectionFlow:
    """Single-owner flow; one instance and queue per TCP connection.

    enter_list() is an explicit permission from the surrounding lifecycle,
    corresponding to a verified list-request path. It must not be called just
    because a LoginResult decoded successfully. No device/auth gates live here.
    close() invalidates the entire supplied connection queue, including ping
    and key-change frames: reconnect requires a new flow and a new queue.
    """
    def __init__(self, outbound: OutboundFrames, limits: SelectionLimits):
        if not isinstance(outbound, OutboundFrames) or not isinstance(limits, SelectionLimits):
            raise TypeError('Expected connection queue and selection limits')
        self._outbound, self._limits = outbound, limits
        self._state = SelectionState.WAITING_ENTRY
        self._characters = None
        self._response = None
        self._raw_f0 = None
        self._deadline = None
        self._last_time = None
        self._error = None
        self._result_code = None
        self._last_packet_id = self._last_body_size = None

    def __repr__(self):
        return f'CharacterSelectionFlow(state={self.state.value}, data=<redacted>)'

    @property
    def state(self): return self._state

    @property
    def characters(self): return self._characters

    @property
    def response(self): return self._response

    @property
    def error(self): return self._error

    @property
    def result_code(self): return self._result_code

    @property
    def last_packet_id(self): return self._last_packet_id

    @property
    def last_body_size(self): return self._last_body_size

    @property
    def preferred_index(self):
        return preferred_character_index(self._characters) if self._characters is not None else None

    @property
    def deadline(self): return self._deadline

    def _time(self, now):
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
            raise ValueError('Expected nonnegative finite monotonic time')
        if self._last_time is not None and now < self._last_time:
            raise ValueError('Selection clock moved backwards')
        self._last_time = now
        return now

    def _expect(self, state):
        if self._state != state:
            raise RuntimeError('Operation is not allowed in selection state ' + self._state.value)

    def _fail(self, error, code=None):
        self._state, self._error, self._result_code = SelectionState.FAILED, error, code
        self._characters = self._response = self._raw_f0 = self._deadline = None
        # A request may still be partly queued when it expires or a malformed
        # response arrives. Never send that stale tail after local failure.
        self._outbound.close()

    def enter_list(self, *, now):
        self._expect(SelectionState.WAITING_ENTRY)
        now = self._time(now)
        deadline = now + self._limits.request_timeout
        if not math.isfinite(deadline):
            raise ValueError('Selection deadline overflow')
        # Queue refusal leaves the request state and sequence untouched.
        self._outbound.queue_character_list()
        self._state, self._deadline = SelectionState.LIST_PENDING, deadline

    def select(self, index, *, now):
        self._expect(SelectionState.LIST_AVAILABLE)
        now = self._time(now)
        payload = CharacterSelectPayload.from_character_list(self._characters, index, state_raw_f0=self._raw_f0)
        deadline = now + self._limits.request_timeout
        if not math.isfinite(deadline):
            raise ValueError('Selection deadline overflow')
        self._outbound.queue_character_select(payload)
        self._state, self._deadline = SelectionState.SELECT_PENDING, deadline

    def update_raw_f0(self, value):
        """Apply an explicit context update before selection, not a guessed ID.

        The native setter can change this field after ID102. The surrounding
        owner must supply such updates from verified events; never silently
        revert to the original list tail when preparing ID109.
        """
        self._expect(SelectionState.LIST_AVAILABLE)
        if type(value) is not int or not 0 <= value <= 0xffffffffffffffff:
            raise ValueError('Expected uint64 selection context')
        self._raw_f0 = value

    def expire(self, *, now):
        """Return True only when an outstanding request has reached its deadline."""
        now = self._time(now)
        if self._deadline is not None and now >= self._deadline:
            self._fail('request_timeout')
            return True
        return False

    def receive(self, packet_id, body, *, now):
        """Route only outstanding ID102/110; return False for unrelated IDs.

        Owner passes one complete decoded body from THIS connection. Framing,
        decompression and key changes belong to the transport. Invalid bodies
        invalidate the connection queue; exceptions never include body data.
        Local policy accepts only code zero. Special nonzero native result
        branches require context not represented by this minimal flow.
        """
        if type(packet_id) is not int or not 0 <= packet_id <= 65535:
            raise ValueError('Expected uint16 packet ID')
        if self._state in (SelectionState.CLOSED, SelectionState.FAILED):
            raise RuntimeError('Selection connection is inactive')
        if self.expire(now=now):
            return False
        if packet_id not in (102, 110):
            return False
        expected = SelectionState.LIST_PENDING if packet_id == 102 else SelectionState.SELECT_PENDING
        self._expect(expected)
        self._last_packet_id = packet_id
        self._last_body_size = len(body) if type(body) is bytes else None
        try:
            if packet_id == 102:
                result = decode_character_list(body, max_payload_size=self._limits.max_payload_size,
                                               max_characters=self._limits.max_characters,
                                               max_extension_items=self._limits.max_collection_items)
            else:
                result = decode_character_select_result(body, max_payload_size=self._limits.max_payload_size,
                                                        max_collection_items=self._limits.max_collection_items)
        except (ValueError, BufferError):
            self._fail('invalid_response')
            raise ValueError('Invalid selection response') from None
        if result.result_code != 0:
            self._fail('unsupported_result_code', result.result_code)
            return True
        self._deadline = None
        self._result_code = 0
        if packet_id == 102:
            self._characters, self._raw_f0 = result, result.tail[3]
            self._state = SelectionState.LIST_AVAILABLE
        else:
            self._response = result
            self._state = SelectionState.SELECT_RESPONSE
        return True

    def close(self):
        """Disconnect/stop; do not reuse this instance after a reconnect."""
        self._outbound.close()
        self._characters = self._response = self._raw_f0 = self._deadline = None
        self._state = SelectionState.CLOSED
