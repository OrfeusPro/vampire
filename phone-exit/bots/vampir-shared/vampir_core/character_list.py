"""Source-bound CharacterListReadResult body with bounded nested containers."""
from dataclasses import dataclass,field
import struct

from .login_result import _text

SOURCE_SHA256='c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'


@dataclass(frozen=True,slots=True)
class CharacterRecord:
    """Raw native offsets; no ID/name/level/position meaning is inferred."""
    strings: tuple[str,...]=field(repr=False)
    u32: tuple[int,...]=field(repr=False)
    u16: tuple[int,...]=field(repr=False)
    u64: tuple[int,...]=field(repr=False)
    enum60: int=field(repr=False)
    appearance: tuple[int,...]=field(repr=False)
    appearance_flags: tuple[int,...]=field(repr=False)
    appearance_items: tuple[tuple[int,int,int],...]=field(repr=False)
    optional_items: tuple[tuple[int,...],...]|None=field(repr=False)
    flag108: bool=field(repr=False)


@dataclass(frozen=True,slots=True)
class CharacterListBody:
    result_code: int
    raw14: int=field(repr=False)
    records: tuple[CharacterRecord,...]=field(repr=False)
    tail: tuple[int,...]=field(repr=False)


def preferred_character_index(body):
    """Native preferred-match rule after acceptance/policy gates, without I/O.

    This suggests an index; it never establishes selection readiness or sends a
    packet. Local policy returns None for an error or empty list (native UI stores
    index zero even when empty). Zero preference skips matching, as in native.
    """
    if not isinstance(body,CharacterListBody):raise ValueError('Expected a decoded character list')
    if body.result_code!=0 or not body.records:return None
    preferred=body.tail[2]
    if preferred!=0:
        for index,record in enumerate(body.records):
            if record.u64[0]==preferred:return index
    return 0


def decode_character_list(body,*,max_payload_size,max_characters,max_extension_items):
    """Read exactly one body with explicit aggregate extension count budget.

    Counts include every wire entry, including duplicate map keys. The map uses
    native last-value-wins semantics and returns entries sorted by their raw key.
    Full response/selection handling remains a separate session responsibility.
    """
    if type(max_payload_size) is not int or not 38<=max_payload_size<=0xffffff:
        raise ValueError('Character list requires a byte budget of 38..16777215')
    if type(max_characters) is not int or not 0<=max_characters<=65535:
        raise ValueError('Character list requires a count budget of 0..65535')
    if type(max_extension_items) is not int or not 0<=max_extension_items<=65535:
        raise ValueError('Character list requires an extension budget of 0..65535')
    if type(body) is not bytes:raise ValueError('Character list input must be immutable bytes')
    if len(body)>max_payload_size:raise BufferError('Character list exceeds byte budget')
    position=0

    def take(size):
        nonlocal position
        end=position+size
        if end>len(body):raise ValueError('Truncated character list')
        data=body[position:end];position=end
        return data

    def number(fmt):return struct.unpack(fmt,take(struct.calcsize(fmt)))[0]

    def text():
        data=take(number('<H'))
        try:value=data.decode('utf-8')
        except UnicodeDecodeError as exc:raise ValueError('Invalid character list UTF-8') from exc
        _text(value)
        return value

    code,raw14,count=number('<I'),number('<I'),number('<H')
    if count>max_characters:raise BufferError('Character count exceeds local budget')
    records=[]
    for _ in range(count):
        u64=[number('<Q')];u32=[number('<I')];strings=[text()]
        u64.append(number('<Q'));u32.append(number('<I'))
        u64.extend((number('<Q'),number('<Q')));strings.append(text())
        enum60=min(number('<B'),6)
        u16=tuple(number('<H') for _ in range(4))
        u64.extend(number('<Q') for _ in range(5))
        appearance=(min(number('<B'),2),)+tuple(number('<B') for _ in range(9))
        strings.append(text())
        appearance_flags=(int(bool(number('<B'))),number('<B'))
        item_count=number('<H')
        if item_count>max_extension_items:raise BufferError('Character extensions exceed aggregate count budget')
        max_extension_items-=item_count
        appearance_items=tuple((number('<I'),min(number('<B'),45),number('<H')) for _ in range(item_count))
        u64.extend(number('<Q') for _ in range(3))
        flag108=bool(number('<B'))
        optional_items=None
        if number('<B')!=0:
            item_count=number('<H')
            if item_count>max_extension_items:raise BufferError('Character extensions exceed aggregate count budget')
            max_extension_items-=item_count
            entries={}
            for _ in range(item_count):
                key=number('<B')
                entries[key]=(key,min(number('<B'),9),number('<I'),number('<I'),number('<I'),number('<Q'))
            optional_items=tuple(sorted(entries.values()))
        records.append(CharacterRecord(tuple(strings),tuple(u32),u16,tuple(u64),enum60,appearance,appearance_flags,
            appearance_items,optional_items,flag108))
    tail=(number('<Q'),number('<I'),number('<Q'),number('<Q'))
    if position!=len(body):raise ValueError('Trailing bytes after character list')
    return CharacterListBody(code,raw14,tuple(records),tail)
