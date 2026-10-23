"""Source-bound ID 104 body; a decoded record is not a successful creation."""
from dataclasses import dataclass, field
import struct

from .character_list import CharacterRecord, decode_character_list
from .world_move_start import SOURCE_SHA256


@dataclass(frozen=True, slots=True)
class CharacterCreateResult:
    result_code: int
    record: CharacterRecord = field(repr=False)


def decode_character_create_result(body, *, source_sha256, max_payload_size, max_extension_items):
    if source_sha256 != SOURCE_SHA256:
        raise ValueError('Unsupported character creation result source')
    if type(body) is not bytes:
        raise ValueError('Character creation result requires immutable bytes')
    if type(max_payload_size) is not int or not 4 <= max_payload_size <= 0xffffff - 34:
        raise ValueError('Invalid character creation result byte budget')
    if len(body) > max_payload_size:
        raise BufferError('Character creation result exceeds byte budget')
    if len(body) < 4:
        raise ValueError('Truncated character creation result')
    # ID 104 has a code followed by the same native record as ID 102.
    # Reuse its bounded record parser through a single-record envelope;
    # synthetic raw14/tail fields are discarded and have no result semantics.
    envelope = body[:4] + struct.pack('<IH', 0, 1) + body[4:] + bytes(28)
    decoded = decode_character_list(envelope, max_payload_size=max_payload_size + 34,
        max_characters=1, max_extension_items=max_extension_items)
    return CharacterCreateResult(decoded.result_code, decoded.records[0])
