"""Source-bound ID104 body; raw offsets do not establish endpoint semantics."""
from dataclasses import dataclass, field
import struct

from .login_result import _text


@dataclass(frozen=True, slots=True)
class LobbyServerGroup:
    raw_08: int
    text_10: str = field(repr=False)
    raw_20: int


@dataclass(frozen=True, slots=True)
class LobbyServerRecord:
    """Ordered object fields, without vptr, padding or guessed names.

    strings: +10/+20/+38; u32: +08/+0c/+4c/+64; u16: +30/+32;
    enums: +34/+35/+60; flags: +48/+49/+4a/+4b/+68; array50: FString array.
    """
    strings: tuple[str, ...] = field(repr=False)
    u32: tuple[int, ...] = field(repr=False)
    u16: tuple[int, ...] = field(repr=False)
    enums: tuple[int, ...] = field(repr=False)
    flags: tuple[bool, ...] = field(repr=False)
    array50: tuple[str, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class LobbyServerListResult:
    result_code: int
    groups: tuple[LobbyServerGroup, ...] = field(repr=False)
    servers: tuple[LobbyServerRecord, ...] = field(repr=False)
    values38: tuple[int, ...] = field(repr=False)
    map48: tuple[tuple[int, int], ...] = field(repr=False)
    map98: tuple[tuple[int, int], ...] = field(repr=False)
    flags: tuple[bool, bool] = field(repr=False)
    enum_e9: int
    strings: tuple[str, str] = field(repr=False)


def decode_lobby_server_list(body, *, max_payload_size, max_collection_items):
    """Decode exactly one ID104 body under explicit byte/aggregate item budgets.

    Map wire entries count toward the budget before duplicate-key replacement.
    Native strings/enum clamps/bool normalization are preserved; text validity
    and exact-tail rejection follow stricter local runtime policy.
    """
    if type(max_payload_size) is not int or not 21 <= max_payload_size <= 0xffffff:
        raise ValueError('Invalid lobby server-list byte budget')
    if type(max_collection_items) is not int or not 0 <= max_collection_items <= 65535:
        raise ValueError('Invalid lobby server-list aggregate item budget')
    if type(body) is not bytes: raise ValueError('Expected immutable lobby server-list body')
    if len(body) > max_payload_size: raise BufferError('Lobby server-list exceeds byte budget')
    position = 0
    remaining = max_collection_items

    def take(size):
        nonlocal position
        end = position + size
        if end > len(body): raise ValueError('Truncated lobby server-list body')
        data = body[position:end]
        position = end
        return data

    def number(fmt): return struct.unpack('<' + fmt, take(struct.calcsize('<' + fmt)))[0]
    def u8(): return number('B')
    def u16(): return number('H')
    def u32(): return number('I')
    def u64(): return number('Q')
    def flag(): return bool(u8())

    def text():
        data = take(u16())
        try: value = data.decode('utf-8')
        except UnicodeDecodeError as exc: raise ValueError('Invalid lobby server-list UTF-8') from exc
        _text(value)
        return value

    def count():
        nonlocal remaining
        n = u16()
        if n > remaining: raise BufferError('Lobby server-list exceeds aggregate item budget')
        remaining -= n
        return n

    def array(item): return tuple(item() for _ in range(count()))

    def mapping(item):
        values = {}
        for _ in range(count()):
            key = u32()
            values[key] = item()
        return tuple(sorted(values.items()))

    def group(): return LobbyServerGroup(u32(), text(), u32())

    def server():
        ids = (u32(), u32())
        first = (text(), text())
        ports = (u16(), u16())
        enums = (min(u8(), 6), min(u8(), 5))
        third = text()
        flags = tuple(flag() for _ in range(4))
        raw4c = u32()
        nested = array(text)
        enum60, raw64, last = min(u8(), 22), u32(), flag()
        return LobbyServerRecord(first + (third,), ids + (raw4c, raw64), ports,
            enums + (enum60,), flags + (last,), nested)

    code = u32()
    groups = array(group)
    servers = array(server)
    values = array(u32)
    map48 = mapping(u32)
    map98 = mapping(u64)
    flag_e8, enum_e9 = flag(), min(u8(), 5)
    strings = (text(), text())
    flag_110 = flag()
    if position != len(body): raise ValueError('Trailing bytes after lobby server-list body')
    return LobbyServerListResult(code, groups, servers, values, map48, map98, (flag_e8, flag_110), enum_e9, strings)
