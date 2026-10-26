"""Verified ID1810 wire for historical/current source; action permission is separate."""
from dataclasses import dataclass
import math
import struct

from .world_move_start import SOURCE_SHA256,CURRENT_PROBE_SOURCE

_WIRE = struct.Struct('<fffQQB')


@dataclass(frozen=True, slots=True, repr=False)
class QuestUpdate:
    vector: tuple[float, float, float]
    raw28: int
    raw30: int
    raw38: int

    def __repr__(self):
        return 'QuestUpdate(data=<redacted>)'


def encode_quest_update(value, *, source_sha256):
    if source_sha256 not in (SOURCE_SHA256,CURRENT_PROBE_SOURCE):
        raise ValueError('Unsupported quest update source')
    if not isinstance(value, QuestUpdate):
        raise TypeError('Expected QuestUpdate')
    if type(value.vector) is not tuple or len(value.vector) != 3:
        raise ValueError('Expected three vector coordinates')
    try:
        finite = all(type(v) in (int, float) and math.isfinite(v) for v in value.vector)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError('Expected finite vector coordinates')
    if any(type(v) is not int or not 0 <= v < 1 << 64 for v in (value.raw28, value.raw30)):
        raise ValueError('Invalid quest update qword')
    if type(value.raw38) is not int or not 0 <= value.raw38 <= 255:
        raise ValueError('Invalid quest update byte')
    try:
        return _WIRE.pack(*value.vector, value.raw28, value.raw30, value.raw38)
    except (OverflowError, struct.error):
        raise ValueError('Quest vector exceeds float32 range') from None


def decode_quest_update(body, *, source_sha256):
    if source_sha256 not in (SOURCE_SHA256,CURRENT_PROBE_SOURCE):
        raise ValueError('Unsupported quest update source')
    if type(body) is not bytes or len(body) != _WIRE.size:
        raise ValueError('Expected 29-byte quest update body')
    x, y, z, a, b, flag = _WIRE.unpack(body)
    if not all(math.isfinite(v) for v in (x, y, z)):
        raise ValueError('Nonfinite quest vector')
    return QuestUpdate((x, y, z), a, b, flag)
