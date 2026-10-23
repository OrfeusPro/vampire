"""Source-bound ID 104 body; a decoded record is not a successful creation."""
from dataclasses import dataclass, field
import struct

from .character_list import CharacterRecord, decode_character_list
from .world_move_start import SOURCE_SHA256


@dataclass(frozen=True, slots=True)
class CharacterCreateResult:
    result_code: int
    record: CharacterRecord = field(repr=False)


@dataclass(frozen=True, slots=True)
class CharacterCreationOutcome:
    status: str
    result_code: int
    character_key: int | None = None
    character_name: str | None = field(default=None, repr=False)
    requested_name_matches: bool = False
    retry_allowed: bool = False


def character_creation_outcome(result, *, source_sha256, requested_name):
    """Local decision after a complete ID 104; never infer name collision.

    Native code zero accepts the returned record even when names differ. Missing
    identity requires a fresh list rather than another creation request.
    """
    if source_sha256 != SOURCE_SHA256 or not isinstance(result, CharacterCreateResult):
        raise ValueError('Unsupported creation result source or type')
    if type(requested_name) is not str or not requested_name or '\0' in requested_name:
        raise ValueError('Expected requested character name')
    if type(result.result_code) is not int or not 0 <= result.result_code <= 0xffffffff:
        raise ValueError('Invalid creation result code')
    if result.result_code != 0:
        # Error records do not identify a created character and must not change
        # an account assignment. No raw error has confirmed name-taken semantics.
        return CharacterCreationOutcome('rejected', result.result_code)
    record = result.record
    if not isinstance(record, CharacterRecord) or not record.u64 or not record.strings:
        raise ValueError('Creation result record has no identity fields')
    key, name = record.u64[0], record.strings[0]
    if type(key) is not int or not 0 <= key <= 0xffffffffffffffff or type(name) is not str or '\0' in name:
        raise ValueError('Invalid created character identity')
    if key == 0 or not name:
        return CharacterCreationOutcome('needs_refresh', 0)
    return CharacterCreationOutcome('created', 0, key, name, name == requested_name)


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
