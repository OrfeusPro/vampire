"""Current ID1811 wire observation; not automatic action confirmation."""
from dataclasses import dataclass, field
from pathlib import Path
import re
import struct
from .quest_record import CURRENT_SOURCE_SHA256, QuestProgress

_WIRE=struct.Struct('<IQBBQQ')


def quest_reply_observation_permitted(source_sha256):
    """Use only the reply proof retained by the active, validated world package."""
    from .bounded_world_admission import SOURCE, current
    if source_sha256 != SOURCE:
        return False
    try:
        profile = current()
    except ValueError:
        return False
    if (not isinstance(profile, dict) or profile.get('schema') != 2 or profile.get('source_sha256') != SOURCE
            or profile.get('world_admitted') is not True or not isinstance(profile.get('policies'), (list, tuple))
            or 'quest-reply-observation-v1' not in profile['policies']
            or not isinstance(profile.get('proofs'), dict) or not isinstance(profile.get('inputs'), dict)):
        return False
    pointer = profile['proofs'].get('quest-reply-current')
    if (not isinstance(pointer, dict) or set(pointer) != {'path', 'sha256'}
            or not isinstance(pointer['path'], str) or not isinstance(pointer['sha256'], str)
            or not re.fullmatch('[a-f0-9]{64}', pointer['sha256'])):
        return False
    path = Path(pointer['path'])
    return (path.is_absolute() and path.name == 'manifest.json' and path.parent.name == pointer['sha256']
            and path.parent.parent.name == 'quest-reply-current-v1'
            and path.parent.parent.parent.name == 'code-clues'
            and profile['inputs'].get(str(path)) == pointer['sha256'])


@dataclass(frozen=True,slots=True)
class QuestUpdateResult:
    result_code: int
    quest_id: int = field(repr=False)
    state: int
    progress: QuestProgress = field(repr=False)


def decode_quest_update_result(body,*,source_sha256):
    if source_sha256!=CURRENT_SOURCE_SHA256 and not quest_reply_observation_permitted(source_sha256):
        raise ValueError('Unsupported quest result source')
    if type(body) is not bytes or len(body)!=_WIRE.size:raise ValueError('Expected complete 30-byte quest result')
    code,key,state,index,a,b=_WIRE.unpack(body)
    return QuestUpdateResult(code,key,min(state,6),QuestProgress(index,a,b))
