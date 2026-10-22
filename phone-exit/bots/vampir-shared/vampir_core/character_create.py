"""Source-bound ID 103 body only; game choices and creation lifecycle are separate."""
from dataclasses import dataclass
import struct

from .world_move_start import SOURCE_SHA256


@dataclass(frozen=True)
class CharacterCreatePayload:
    raw_class: int
    name: str
    appearance: tuple[int, ...]
    appearance_text: str
    raw_flags: tuple[int, int]
    items: tuple[tuple[int, int, int], ...]


def encode_character_create(value, *, source_sha256):
    if source_sha256 != SOURCE_SHA256 or not isinstance(value, CharacterCreatePayload):
        raise ValueError('Unsupported character creation source or payload')
    def integer(number, maximum):
        if type(number) is not int or not 0 <= number <= maximum:
            raise ValueError('Invalid character creation integer')
        return number
    def text(string):
        if type(string) is not str or '\0' in string:
            raise ValueError('Expected terminated character creation string')
        try:
            data = string.encode('utf-8')
        except UnicodeError as error:
            raise ValueError('Invalid character creation Unicode') from error
        # Local memory budget, not a claim about the server's name/JSON policy.
        if len(data) > 4096:
            raise ValueError('Character creation string budget exceeded')
        return struct.pack('<H', len(data)) + data
    if (type(value.appearance) is not tuple or len(value.appearance) != 10
            or type(value.raw_flags) is not tuple or len(value.raw_flags) != 2
            or type(value.items) is not tuple or len(value.items) > 256):
        raise ValueError('Invalid character creation field counts')
    appearance = bytes(integer(number, 255) for number in value.appearance)
    flags = bytes(integer(number, 255) for number in value.raw_flags)
    items = []
    for row in value.items:
        if type(row) is not tuple or len(row) != 3:
            raise ValueError('Invalid character creation item')
        items.append(struct.pack('<IBH', integer(row[0], 0xffffffff), integer(row[1], 255), integer(row[2], 0xffff)))
    # Produce the complete immutable body before it can reach a transport.
    # Raw enum/bool bytes are preserved, matching the native writer, not reader clamps.
    return (struct.pack('<I', integer(value.raw_class, 0xffffffff)) + text(value.name)
        + appearance + text(value.appearance_text) + flags + struct.pack('<H', len(items)) + b''.join(items))
