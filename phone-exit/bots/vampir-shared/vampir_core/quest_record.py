"""Current PktQuest value only; list envelope and gameplay semantics are separate."""
from dataclasses import dataclass, field
import struct

from .world_move_start import SOURCE_SHA256


@dataclass(frozen=True, slots=True)
class QuestProgress:
    raw08: int
    raw10: int
    raw18: int


@dataclass(frozen=True, slots=True)
class QuestRecord:
    raw08: int = field(repr=False)
    raw10: int
    progress: QuestProgress = field(repr=False)
    raw38: bool
    raw3c: int
    raw40: int
    raw44: int


def decode_quest_record(body, *, source_sha256):
    if source_sha256 != SOURCE_SHA256:
        raise ValueError('Unsupported quest record source')
    if type(body) is not bytes or len(body) != 39:
        raise ValueError('Invalid quest record body')
    key, state, progress_kind, a, b, flag, c, d, e = struct.unpack('<QBBQQBIII', body)
    return QuestRecord(key, min(state, 6), QuestProgress(progress_kind, a, b),
                       bool(flag), c, d, e)
