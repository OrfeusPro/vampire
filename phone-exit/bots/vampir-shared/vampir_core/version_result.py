"""Verified ID2 body; exact-size local policy is stricter than native reader."""
from dataclasses import dataclass, field
import struct


@dataclass(frozen=True, slots=True)
class VersionResultBody:
    result_code: int
    raw14: int = field(repr=False)
    flag18: bool = field(repr=False)
    raw1c: int = field(repr=False)
    raw20: int = field(repr=False)


def decode_version_result(body):
    if type(body) is not bytes or len(body) != 17:
        raise ValueError('VersionResult requires exactly 17 bytes')
    code, raw14, flag, raw1c, raw20 = struct.unpack('<IIBII', body)
    return VersionResultBody(code, raw14, bool(flag), raw1c, raw20)
