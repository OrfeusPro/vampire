"""Bounded source-bound ID9905 data; field meaning requires handler evidence."""
from dataclasses import dataclass, field
import struct

from .world_move_start import SOURCE_SHA256,CURRENT_PROBE_SOURCE

TUTORIAL_SOURCES=frozenset((SOURCE_SHA256,CURRENT_PROBE_SOURCE))


@dataclass(frozen=True, slots=True)
class TutorialRecord:
    raw08: int
    raw0c: int
    raw10: int
    state: int


@dataclass(frozen=True, slots=True)
class TutorialUpdate:
    flag: bool
    records: tuple[TutorialRecord, ...] = field(repr=False)


def decode_tutorial_update(body, *, source_sha256, max_records, max_payload_size):
    if source_sha256 not in TUTORIAL_SOURCES:raise ValueError('Unsupported tutorial source')
    if type(max_records) is not int or not 0<=max_records<=65535:
        raise ValueError('Explicit tutorial record budget required')
    if type(max_payload_size) is not int or not 3<=max_payload_size<=0xffffff:
        raise ValueError('Explicit tutorial byte budget required')
    if type(body) is not bytes or len(body)<3:raise ValueError('Invalid tutorial body')
    if len(body)>max_payload_size:raise BufferError('Tutorial byte budget exceeded')
    count=struct.unpack_from('<H',body,1)[0]
    if count>max_records:raise BufferError('Tutorial record budget exceeded')
    if len(body)!=3+13*count:raise ValueError('Tutorial body size differs')
    return TutorialUpdate(bool(body[0]),tuple(TutorialRecord(a,b,c,min(state,3))
        for a,b,c,state in struct.iter_unpack('<IIIB',body[3:])))
