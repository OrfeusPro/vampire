"""Exact current1803/1804 wire. The owner separately admits a manual attempt."""
from dataclasses import dataclass, field
import struct
from .quest_sync import QuestSync, decode_quest_sync

SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'


def encode_quest_start(quest_id, *, source_sha256):
    if source_sha256 != SOURCE:
        raise ValueError('Unsupported QuestStart source')
    if type(quest_id) is not int or not 0 < quest_id < 2**64:
        raise ValueError('Explicit positive QuestInfoId required')
    return struct.pack('<Q', quest_id)


@dataclass(frozen=True, slots=True)
class QuestStartResult:
    result_code: int
    quest_id: int = field(repr=False)
    data: QuestSync = field(repr=False)


def decode_quest_start_result(body, *, source_sha256):
    if source_sha256 != SOURCE:
        raise ValueError('Unsupported QuestStart result source')
    if type(body) is not bytes or not 22 <= len(body) <= 2542:
        raise ValueError('Expected bounded complete QuestStartResult')
    code, key = struct.unpack_from('<IQ', body)
    nested = decode_quest_sync(body[12:], source_sha256=source_sha256,
        max_collection_items=8, max_total_items=72, max_payload_size=2530)
    return QuestStartResult(code, key, nested)
