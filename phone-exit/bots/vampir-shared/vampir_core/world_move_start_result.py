"""Bounded ID204 body, verified against the current Windows native reader."""
from dataclasses import dataclass, field
import struct

from .character_select_result import SelectionRecord, WireVector3, SOURCE_SHA256


@dataclass(frozen=True, slots=True)
class WorldMoveStartResultBody:
    result_code: int
    data: SelectionRecord = field(repr=False)


def decode_world_move_start_result(body, *, max_payload_size):
    """Consume exactly one ID204 body without applying result/state policy.

Field offsets refer to the native packet object, not byte offsets in the body.
The vector retains raw float32 bits; world-coordinate semantics are unverified.
"""
    if type(max_payload_size) is not int or not 30 <= max_payload_size <= 0xffffff:
        raise ValueError('World start byte budget must be 30..16777215')
    if type(body) is not bytes:
        raise ValueError('World start result requires immutable bytes')
    if len(body) > max_payload_size:
        raise BufferError('World start result exceeds byte budget')
    if len(body) != 30:
        raise ValueError('World start result must contain exactly 30 bytes')
    code, world, a, b, c, kind, flag, payload = struct.unpack('<IIIIIBBQ', body)
    data = SelectionRecord(((0x14, world), (0x18, WireVector3((a, b, c))),
                            (0x30, min(kind, 22)), (0x31, bool(flag)), (0x38, payload)))
    return WorldMoveStartResultBody(code, data)
