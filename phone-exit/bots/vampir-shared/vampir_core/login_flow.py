"""Local Version -> Login lifecycle with explicit, already prepared fields.

Sources: HEADLESS-VERSION-RESULT-HANDLER / LOGIN-SEND-PATH /
LOGIN-RESULT-READER. Does not generate identity, call SDK or load the world.
"""
import math
import struct

from .login_packet import LoginPayload
from .login_result import decode_login_result
from .login_result_current import decode_current_login_result, SOURCE_SHA256 as CURRENT_RESULT_SOURCE
from .version_result import decode_version_result


class LoginFlow:
    def __init__(self, outbound, *, timeout, max_payload_size):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('Expected positive finite login timeout')
        if type(max_payload_size) is not int or not 99 <= max_payload_size <= 0xffffff:
            raise ValueError('Expected Login payload limit of 99..16777215')
        self._outbound = outbound
        self._timeout, self._limit = timeout, max_payload_size
        self.state = 'new'
        self.error = self.result_code = self.response = self.deadline = None
        self._login = None
        self._last_time = None
        self.version_result_code = self.login_result_code = self.last_body_size = None
        self.response_failure = None

    def __repr__(self): return f'LoginFlow(state={self.state}, data=<redacted>)'

    def _time(self, now):
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
            raise ValueError('Expected finite monotonic time')
        if self._last_time is not None and now < self._last_time:
            raise ValueError('Login clock moved backwards')
        if not math.isfinite(now + self._timeout): raise ValueError('Login deadline overflow')
        self._last_time = now
        return now

    def start(self, version, login, *, now):
        if self.state != 'new': raise RuntimeError('Login flow already started')
        if not isinstance(login, LoginPayload): raise TypeError('Expected LoginPayload')
        login.encode(max_payload_size=self._limit)
        now = self._time(now)
        self._outbound.queue_version(version, max_payload_size=self._limit)
        self._login, self.deadline, self.state = login, now + self._timeout, 'version_pending'

    def _fail(self, reason, code=None):
        self.state, self.error, self.result_code = 'failed', reason, code
        self._login = self.response = self.deadline = None
        self._outbound.close()

    def expire(self, *, now):
        now = self._time(now)
        if self.deadline is not None and now >= self.deadline:
            self._fail('request_timeout')
            return True
        return False

    def receive(self, packet_id, body, *, now):
        if packet_id not in (2, 4): return False
        expected = 'version_pending' if packet_id == 2 else 'login_pending'
        if self.state != expected: raise RuntimeError('Unexpected login response')
        if self.expire(now=now): return False
        operation = 'decode_version' if packet_id == 2 else 'decode_login'
        try:
            from .bounded_entry_admission import permits
            if packet_id == 2:
                result = decode_version_result(body)
            elif permits(CURRENT_RESULT_SOURCE, 'game-login-current-layout-v1'):
                result = decode_current_login_result(body, max_payload_size=self._limit,
                                                    source_sha256=CURRENT_RESULT_SOURCE)
            else:
                result = decode_login_result(body, max_payload_size=self._limit)
            self.last_body_size = len(body)
            if packet_id == 2: self.version_result_code = result.result_code
            else: self.login_result_code = result.result_code
            if result.result_code != 0:
                self._fail('unsupported_result_code', result.result_code)
                return True
            if packet_id == 2:
                operation = 'queue_login'
                self._outbound.queue_login(self._login, max_payload_size=self._limit)
                self._login = None
                self.state, self.deadline = 'login_pending', now + self._timeout
            else:
                self.state, self.response, self.result_code, self.deadline = 'login_response', result, 0, None
        except (ValueError, BufferError) as error:
            self.response_failure = dict(packet_id=packet_id, body_size=len(body), operation=operation,
                error_type=type(error).__name__, result_prefix=struct.unpack_from('<I', body)[0] if len(body) >= 4 else None,
                result_prefix_validated=False)
            self._fail('invalid_response_or_queue_refusal')
            raise ValueError('Login response processing failed') from None
        return True

    def close(self):
        self._login = self.response = self.deadline = None
        self.state = 'closed'
