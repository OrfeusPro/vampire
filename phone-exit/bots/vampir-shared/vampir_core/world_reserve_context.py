"""Current ID202 fields consumed by the start transition; opaque suffix.

This is a bounded envelope policy, not validation of the complete native body.
Nested world collections, vector and tail remain uninterpreted. No IO.
"""
from dataclasses import dataclass, field
import struct

from .world_move_start import SOURCE_SHA256, WORLD_PROBE_SOURCES
from .runtime_admission import permits


@dataclass(frozen=True, slots=True)
class WorldReserveContext:
    result_code: int
    raw14: int = field(repr=False)
    raw20: int = field(repr=False)
    raw28: int = field(repr=False)
    flag2c: bool = field(repr=False)
    raw2d: int = field(repr=False)
    opaque_suffix: bytes = field(repr=False)


def decode_world_reserve_context(body, *, max_payload_size, source_sha256):
    """Decode result/enum/nested18, retain remaining bytes without accepting them.

    Consumers may use these proven fields for a protocol step but must not call
    the whole ID202 body validated or use opaque world data as game state.
    """
    if source_sha256 not in WORLD_PROBE_SOURCES and not permits(source_sha256,'world-selection-move-v1'):
        raise ValueError('World reserve context policy is not verified for source')
    if type(max_payload_size) is not int or not 19 <= max_payload_size <= 0xffffff:
        raise ValueError('World reserve context requires an explicit byte budget')
    if type(body) is not bytes: raise ValueError('Expected immutable reserve bytes')
    if len(body)>max_payload_size: raise BufferError('World reserve context exceeds budget')
    if len(body)<19: raise ValueError('Truncated world reserve context')
    code,kind,raw20,raw28,flag,reason=struct.unpack_from('<IBQIBB',body)
    return WorldReserveContext(code,min(kind,32),raw20,raw28,bool(flag),min(reason,22),body[19:])
