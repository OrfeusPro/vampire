"""Current PktQuest value only; list envelope and gameplay semantics are separate."""
from dataclasses import dataclass, field
import struct

from .world_move_start import SOURCE_SHA256

CURRENT_SOURCE_SHA256 = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


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
    from .bounded_world_admission import permits
    if source_sha256 not in (SOURCE_SHA256, CURRENT_SOURCE_SHA256) and not permits(source_sha256, 'quest-observation-v1'):
        raise ValueError('Unsupported quest record source')
    if type(body) is not bytes or len(body) != 39:
        raise ValueError('Invalid quest record body')
    key, state, progress_kind, a, b, flag, c, d, e = struct.unpack('<QBBQQBIII', body)
    return QuestRecord(key, min(state, 6), QuestProgress(progress_kind, a, b),
                       bool(flag), c, d, e)
