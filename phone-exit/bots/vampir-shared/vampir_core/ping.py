"""Shared Vampir Ping payload bits for the investigated build, excluding framing.

Source and native reference vectors: resource-tools/vampir/HEADLESS-PING-CODEC.md.
Values are unsigned bit patterns; field semantics and session timing are unknown.
"""
import struct
from dataclasses import dataclass

SOURCE_SHA256 = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'
_PING = struct.Struct('<QQ')
_RESULT = struct.Struct('<IQ')


def _bits(value, width):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << width:
        raise ValueError(f'Expected unsigned {width}-bit pattern')


@dataclass(frozen=True, slots=True)
class PingPayload:
    first_bits: int
    second_bits: int

    def __post_init__(self):
        _bits(self.first_bits, 64)
        _bits(self.second_bits, 64)

    def encode(self):
        return _PING.pack(self.first_bits, self.second_bits)

    @classmethod
    def decode(cls, payload):
        if len(payload) != _PING.size:
            raise ValueError('Ping payload must contain exactly 16 bytes')
        return cls(*_PING.unpack(payload))


@dataclass(frozen=True, slots=True)
class PingResultPayload:
    result_bits: int
    value_bits: int

    def __post_init__(self):
        _bits(self.result_bits, 32)
        _bits(self.value_bits, 64)

    def encode(self):
        return _RESULT.pack(self.result_bits, self.value_bits)

    @classmethod
    def decode(cls, payload):
        if len(payload) != _RESULT.size:
            raise ValueError('Ping result payload must contain exactly 12 bytes')
        return cls(*_RESULT.unpack(payload))
