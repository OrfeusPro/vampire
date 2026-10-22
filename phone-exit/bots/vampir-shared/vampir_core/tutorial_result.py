"""Current ID 9904 wire data; flags and server state application remain separate."""
from dataclasses import dataclass, field
import struct

from .tutorial_update import TutorialRecord
from .world_move_start import SOURCE_SHA256


@dataclass(frozen=True, slots=True)
class TutorialResult:
    code: int
    record: TutorialRecord = field(repr=False)
    raw30: bool
    raw31: bool


def decode_tutorial_result(body, *, source_sha256):
    if source_sha256 != SOURCE_SHA256:
        raise ValueError('Unsupported tutorial result source')
    if type(body) is not bytes or len(body) != 19:
        raise ValueError('Invalid tutorial result body')
    code, key, selector, raw10, state, raw30, raw31 = struct.unpack('<IIIIBBB', body)
    return TutorialResult(code, TutorialRecord(key, selector, raw10, min(state, 3)),
                          bool(raw30), bool(raw31))
