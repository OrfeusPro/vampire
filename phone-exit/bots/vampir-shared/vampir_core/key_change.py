"""Key-change payload codec for the investigated build; no session management.

Native order: send KeyChanged acknowledgement, then set the new peer key.
Evidence: HEADLESS-KEY-CHANGE.md. Do not log live key values.
"""
import struct
from dataclasses import dataclass
from .ping import SOURCE_SHA256

KEY_CHANGE_NOTIFY_ID = 11
KEY_CHANGED_ID = 12
_BITS = struct.Struct('<Q')


@dataclass(frozen=True, slots=True, repr=False)
class KeyChangePayload:
    key_bits: int

    def __post_init__(self):
        if isinstance(self.key_bits, bool) or not isinstance(self.key_bits, int) or not 0 <= self.key_bits < 1 << 64:
            raise ValueError('Expected unsigned 64-bit key pattern')

    def __repr__(self):
        return 'KeyChangePayload(<redacted>)'

    def encode(self) -> bytes:
        return _BITS.pack(self.key_bits)

    @classmethod
    def decode(cls, payload: bytes):
        if len(payload) != _BITS.size:
            raise ValueError('Key-change payload must contain exactly8 bytes')
        return cls(_BITS.unpack(payload)[0])
