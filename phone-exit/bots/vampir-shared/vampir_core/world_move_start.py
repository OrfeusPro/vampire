"""Current ID203 body from the accepted current selected-player record. No IO."""
from dataclasses import dataclass, field
import struct

from .character_select_result import CharacterSelectResultBody

SOURCE_SHA256 = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
CURRENT_PROBE_SOURCE = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
# Explicit bounded probe policy; strict historical nested decoders may refuse new bodies.
WORLD_PROBE_SOURCES = frozenset((SOURCE_SHA256, CURRENT_PROBE_SOURCE))


@dataclass(frozen=True, slots=True)
class WorldMoveStartPayload:
    raw10: int = field(repr=False)

    def __post_init__(self):
        if type(self.raw10) is not int or not 0 <= self.raw10 < 2**64:
            raise ValueError('WorldMoveStart requires a uint64 field')

    @classmethod
    def from_selection(cls, selection, *, source_sha256):
        if source_sha256 not in WORLD_PROBE_SOURCES:
            raise ValueError('WorldMoveStart source policy is not verified')
        if not isinstance(selection,CharacterSelectResultBody) or selection.result_code != 0:
            raise ValueError('WorldMoveStart requires an accepted current selection')
        # current apply main+8 -> player+8 -> current request packet+0x10.
        # The session owner must also establish the accepted ID202 gate.
        return cls(selection.player.at(8))

    def encode(self, *, max_payload_size):
        if type(max_payload_size) is not int or not 0 <= max_payload_size <= 0xffffff:
            raise ValueError('WorldMoveStart requires an explicit byte budget')
        if max_payload_size < 8:
            raise BufferError('WorldMoveStart exceeds byte budget')
        return struct.pack('<Q',self.raw10)
