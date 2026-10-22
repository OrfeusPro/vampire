"""Current ID 1802 with empty item-change suffix; other suffixes fail explicitly."""
from dataclasses import dataclass, field
import struct

from .quest_record import QuestRecord, decode_quest_record
from .world_move_start import SOURCE_SHA256


@dataclass(frozen=True, slots=True)
class AssetChange:
    raw08: int
    raw10: int = field(repr=False)
    raw18: int = field(repr=False)


@dataclass(frozen=True, slots=True)
class EmptyItemChangeList:
    counts: tuple[int, int, int, int] = (0, 0, 0, 0)


@dataclass(frozen=True, slots=True)
class QuestListResult:
    code: int
    raw14: int
    quests: tuple[QuestRecord, ...] = field(repr=False)
    assets: tuple[AssetChange, ...] = field(repr=False)
    raw38: bool
    raw39: bool
    item_changes: EmptyItemChangeList = field(repr=False)


def decode_quest_list_result(body, *, source_sha256, max_collection_items,
                             max_total_items, max_payload_size):
    if source_sha256 != SOURCE_SHA256:
        raise ValueError('Unsupported quest list source')
    for value, maximum in ((max_collection_items, 65535), (max_total_items, 1048576),
                            (max_payload_size, 0xffffff)):
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError('Explicit bounded quest list limits required')
    if type(body) is not bytes:
        raise ValueError('Invalid quest list body')
    if len(body) > max_payload_size:
        raise BufferError('Quest list byte budget exceeded')
    at = total = 0

    def take(size):
        nonlocal at
        if size > len(body) - at:
            raise ValueError('Truncated quest list body')
        value = body[at:at + size]
        at += size
        return value

    def count():
        nonlocal total
        n = struct.unpack('<H', take(2))[0]
        if n > max_collection_items or total + n > max_total_items:
            raise BufferError('Quest list collection budget exceeded')
        total += n
        return n

    def quests():
        return tuple(decode_quest_record(take(39), source_sha256=source_sha256)
                     for _ in range(count()))

    code = struct.unpack('<I', take(4))[0]
    raw14 = min(take(1)[0], 12)
    records = quests()
    assets = []
    for _ in range(count()):
        kind, a, b = struct.unpack('<BQQ', take(17))
        assets.append(AssetChange(min(kind, 97), a, b))
    raw38, raw39 = (bool(value) for value in take(2))
    # Actual packet constructor sets PktItemChangeList here, not PktQuestData.
    # Do not invent or skip variable-length item records before proving them.
    for _ in range(4):
        if count():
            raise ValueError('Nonempty quest item changes are not supported')
    if at != len(body):
        raise ValueError('Trailing quest list bytes')
    return QuestListResult(code, raw14, records, tuple(assets), raw38, raw39,
                           EmptyItemChangeList())
