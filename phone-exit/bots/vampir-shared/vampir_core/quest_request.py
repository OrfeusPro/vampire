"""Current ID 1801 body; raw18 meaning and request lifecycle are separate."""
import struct

from .world_move_start import SOURCE_SHA256


def encode_quest_list_read(raw10, raw18, *, source_sha256):
    if source_sha256 != SOURCE_SHA256:
        raise ValueError('Unsupported quest list request source')
    for value, maximum in ((raw10, 255), (raw18, 0xffffffffffffffff)):
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError('Invalid quest list request field')
    return struct.pack('<BQ', raw10, raw18)
