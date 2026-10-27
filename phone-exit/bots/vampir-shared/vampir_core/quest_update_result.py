"""Current ID1811 wire observation; not automatic action confirmation."""
from dataclasses import dataclass, field
import struct
from .quest_record import CURRENT_SOURCE_SHA256, QuestProgress

_WIRE=struct.Struct('<IQBBQQ')


@dataclass(frozen=True,slots=True)
class QuestUpdateResult:
    result_code: int
    quest_id: int = field(repr=False)
    state: int
    progress: QuestProgress = field(repr=False)


def decode_quest_update_result(body,*,source_sha256):
    if source_sha256!=CURRENT_SOURCE_SHA256:raise ValueError('Unsupported quest result source')
    if type(body) is not bytes or len(body)!=_WIRE.size:raise ValueError('Expected complete 30-byte quest result')
    code,key,state,index,a,b=_WIRE.unpack(body)
    return QuestUpdateResult(code,key,min(state,6),QuestProgress(index,a,b))
