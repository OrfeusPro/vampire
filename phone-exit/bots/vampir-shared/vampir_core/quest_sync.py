"""Bounded ID1854 wire snapshot. No active-quest or gameplay interpretation."""
from dataclasses import dataclass, field
import struct

from .quest_record import CURRENT_SOURCE_SHA256, QuestRecord, decode_quest_record


@dataclass(frozen=True, slots=True)
class QuestGroup:
    raw08: int
    quests: tuple[QuestRecord, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class QuestSync:
    groups: tuple[QuestGroup, ...] = field(repr=False)
    raw18: int = field(repr=False)


def decode_quest_sync(body, *, source_sha256, max_collection_items,
                      max_total_items, max_payload_size):
    if source_sha256 != CURRENT_SOURCE_SHA256:
        raise ValueError('Unsupported quest sync source')
    for limit, maximum in ((max_collection_items, 65535),
                           (max_total_items, 1048576), (max_payload_size, 0xffffff)):
        if type(limit) is not int or not 0 <= limit <= maximum:
            raise ValueError('Explicit bounded quest sync limits required')
    if type(body) is not bytes:
        raise ValueError('Invalid quest sync body')
    if len(body) > max_payload_size:
        raise BufferError('Quest sync byte budget exceeded')
    at = total = 0

    def take(size):
        nonlocal at
        if size > len(body) - at:
            raise ValueError('Truncated quest sync body')
        value = body[at:at + size]
        at += size
        return value

    def count():
        nonlocal total
        n = struct.unpack('<H', take(2))[0]
        if n > max_collection_items or total + n > max_total_items:
            raise BufferError('Quest sync collection budget exceeded')
        total += n
        return n

    groups = []
    for _ in range(count()):
        kind = min(take(1)[0], 12)
        quests = tuple(decode_quest_record(take(39), source_sha256=source_sha256)
                       for _ in range(count()))
        groups.append(QuestGroup(kind, quests))
    suffix = struct.unpack('<Q', take(8))[0]
    if at != len(body):
        raise ValueError('Trailing quest sync bytes')
    return QuestSync(tuple(groups), suffix)
