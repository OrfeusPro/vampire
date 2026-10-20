"""Separate lobby ID 4 response; never decode it as the game LoginResult."""
from dataclasses import dataclass, field
import struct

from .login_packet import _utf8


@dataclass(frozen=True, slots=True)
class LobbyLoginResultBody:
    """Raw fields: u32 +10/+14/+18/+70; strings +20/+30/+40/+50/+60.

    Names and units beyond the handler's result_code are not inferred.
    """
    strings: tuple[str, ...] = field(repr=False)
    integers: tuple[int, ...] = field(repr=False)

    def __post_init__(self):
        if type(self.strings) is not tuple or len(self.strings) != 5:
            raise ValueError('Expected five immutable lobby response strings')
        for text in self.strings: _utf8(text)
        if (type(self.integers) is not tuple or len(self.integers) != 4 or
                any(type(n) is not int or not 0 <= n <= 0xffffffff for n in self.integers)):
            raise ValueError('Expected four uint32 lobby response fields')

    @property
    def result_code(self):
        return self.integers[0]


def decode_lobby_login_result(body, *, max_payload_size):
    """Decode one bounded lobby response; reject extra bytes as local policy."""
    if type(max_payload_size) is not int or not 26 <= max_payload_size <= 0xffffff:
        raise ValueError('Lobby response byte budget must be 26..16777215')
    if type(body) is not bytes: raise ValueError('Expected immutable lobby body')
    if len(body) > max_payload_size: raise BufferError('Lobby response exceeds byte budget')
    if len(body) < 26: raise ValueError('Truncated lobby response')
    position = 0

    def take(size):
        nonlocal position
        end = position + size
        if end > len(body): raise ValueError('Truncated lobby response field')
        data = body[position:end]
        position = end
        return data

    integers = struct.unpack('<III', take(12))
    strings = []
    for _ in range(5):
        size = int.from_bytes(take(2), 'little')
        try: text = take(size).decode('utf-8')
        except UnicodeDecodeError as exc: raise ValueError('Invalid lobby response UTF-8') from exc
        strings.append(text)
    integers += (int.from_bytes(take(4), 'little'),)
    if position != len(body): raise ValueError('Trailing bytes after lobby response')
    return LobbyLoginResultBody(tuple(strings), integers)
