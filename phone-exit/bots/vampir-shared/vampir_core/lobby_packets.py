"""Separate lobby handshake/list bodies; no game packet ID interpretation."""
from dataclasses import dataclass, field
import struct

from .login_packet import _utf8, _numbers


def _strings(values, count):
    if type(values) is not tuple or len(values) != count:
        raise ValueError('Expected immutable ordered lobby strings')
    return tuple(_utf8(value) for value in values)


def _budget(value, minimum):
    if type(value) is not int or not minimum <= value <= 0xffffff:
        raise ValueError('Invalid lobby payload byte budget')


def _encode_texts(values):
    return tuple(struct.pack('<H', len(value)) + value for value in values)


@dataclass(frozen=True, slots=True)
class LobbyVersionPayload:
    """ID 1: strings +18/+28/+40/+50/+60, raw bytes +10/+38, uint32 +70.

    All values explicit. Source of values and server acceptance belong to the
    connection owner; this encoder does not read or generate device identity.
    """
    strings: tuple[str, ...] = field(repr=False)
    raw_bytes: tuple[int, ...] = field(repr=False)
    raw_70: int = field(repr=False)

    def __post_init__(self):
        _strings(self.strings, 5)
        _numbers(self.raw_bytes, 2, 255)
        _numbers((self.raw_70,), 1, 0xffffffff)

    def encode(self, *, max_payload_size):
        _budget(max_payload_size, 16)
        texts = _strings(self.strings, 5)
        if 16 + sum(map(len, texts)) > max_payload_size: raise BufferError('Lobby Version exceeds byte budget')
        parts = _encode_texts(texts)
        return (bytes([self.raw_bytes[0]]) + b''.join(parts[:2]) + bytes([self.raw_bytes[1]]) +
            b''.join(parts[2:]) + struct.pack('<I', self.raw_70))


@dataclass(frozen=True, slots=True)
class LobbyLoginPayload:
    """ID3: u32 +10/+14, strings +18/+28/+38/+48/+58, u32 +68/+6c,
    string +70, raw byte +80. No inferred profile defaults or SDK IO.
    """
    strings: tuple[str, ...] = field(repr=False)
    integers: tuple[int, ...] = field(repr=False)
    raw_80: int = field(repr=False)

    def __post_init__(self):
        _strings(self.strings, 6)
        _numbers(self.integers, 4, 0xffffffff)
        _numbers((self.raw_80,), 1, 255)

    def encode(self, *, max_payload_size):
        _budget(max_payload_size, 29)
        texts = _strings(self.strings, 6)
        if 29 + sum(map(len, texts)) > max_payload_size: raise BufferError('Lobby Login exceeds byte budget')
        parts = _encode_texts(texts)
        return (struct.pack('<II', *self.integers[:2]) + b''.join(parts[:5]) +
            struct.pack('<II', *self.integers[2:]) + parts[5] + bytes([self.raw_80]))


@dataclass(frozen=True, slots=True)
class LobbyServerListPayload:
    """ID 103: strings +10/+20, uint32 +30, raw bytes +34/+35.

    The native writer preserves both byte values, including bool slot +35.
    """
    strings: tuple[str, ...] = field(repr=False)
    raw_30: int = field(repr=False)
    raw_bytes: tuple[int, ...] = field(repr=False)

    def __post_init__(self):
        _strings(self.strings, 2)
        _numbers((self.raw_30,), 1, 0xffffffff)
        _numbers(self.raw_bytes, 2, 255)

    def encode(self, *, max_payload_size):
        _budget(max_payload_size, 10)
        texts = _strings(self.strings, 2)
        if 10 + sum(map(len, texts)) > max_payload_size: raise BufferError('Lobby list request exceeds byte budget')
        return b''.join(_encode_texts(texts)) + struct.pack('<I', self.raw_30) + bytes(self.raw_bytes)


@dataclass(frozen=True, slots=True)
class LobbyVersionResultBody:
    """ID 2: result +10, normalized bool +14, raw TimeBase bits +20/+30, u16 +38."""
    result_code: int
    flag_14: bool
    time_bits: tuple[int, ...] = field(repr=False)
    raw_38: int = field(repr=False)

    def __post_init__(self):
        _numbers((self.result_code,), 1, 0xffffffff)
        if type(self.flag_14) is not bool: raise ValueError('Expected normalized lobby response bool')
        _numbers(self.time_bits, 2, 0xffffffffffffffff)
        _numbers((self.raw_38,), 1, 65535)


def decode_lobby_version_result(body):
    """Exactly 23 bytes; portable policy rejects any native-unconsumed tail."""
    if type(body) is not bytes or len(body) != 23:
        raise ValueError('Expected one complete lobby VersionResult body')
    code, flag, first, second, raw = struct.unpack('<IBQQH', body)
    return LobbyVersionResultBody(code, bool(flag), (first, second), raw)


def make_windows_lobby_login(*, version_result, kind, selected_server_id, metadata):
    """Native Windows numeric branch with Version flag +14 off.

    kind, selected server and metadata are explicit source-context inputs, not
    inferred initial values. Five identity strings remain for the SDK binder.
    Constructor preserves raw +80=7, not a normalized boolean.
    """
    if not isinstance(version_result, LobbyVersionResultBody):
        raise TypeError('Expected separate lobby VersionResult')
    if version_result.result_code != 0: raise ValueError('Lobby Version did not succeed')
    if version_result.flag_14:
        raise NotImplementedError('Version flag requires additional numeric context')
    _numbers((kind, selected_server_id), 2, 0xffffffff)
    _utf8(metadata)
    return LobbyLoginPayload(('',) * 5 + (metadata,), (2, 2 if kind == 2 else 0, selected_server_id, 0), 7)
