"""Current incoming ID306/307 bodies. No entity ownership or movement commands."""
from dataclasses import dataclass, field
import math
import struct

from .world_move_start import SOURCE_SHA256


@dataclass(frozen=True, slots=True)
class CharacterMoveNotify:
    entity_key: int = field(repr=False)
    xy_bits: tuple[int, int] = field(repr=False)

    def finite_xy(self):
        xy = struct.unpack('<ff', struct.pack('<II', *self.xy_bits))
        if not all(math.isfinite(v) for v in xy):
            raise ValueError('Nonfinite movement coordinates')
        return xy


def _body(payload, size, source_sha256):
    if source_sha256 != SOURCE_SHA256:
        raise ValueError('Movement event source is not verified')
    if not isinstance(payload, bytes) or len(payload) != size:
        raise ValueError('Movement event body size differs')
    return payload


def decode_move_notify(payload, *, source_sha256):
    key, x, y = struct.unpack('<QII', _body(payload, 16, source_sha256))
    return CharacterMoveNotify(key, (x, y))


def decode_move_result(payload, *, source_sha256):
    # Raw field only; its error enum and command acknowledgement are unproven.
    return struct.unpack('<I', _body(payload, 4, source_sha256))[0]
