"""Current ID 9903 body only; callers must establish action and response semantics."""
import struct

from .world_move_start import SOURCE_SHA256


def encode_tutorial_request(key, selector, raw18, *, source_sha256):
    if source_sha256 != SOURCE_SHA256:
        raise ValueError('Unsupported tutorial request source')
    for value, maximum in ((key, 0xffffffff), (selector, 0xffffffff), (raw18, 255)):
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError('Invalid tutorial request field')
    return struct.pack('<IIB', key, selector, raw18)
