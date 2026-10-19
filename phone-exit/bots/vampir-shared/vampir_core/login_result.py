"""Verified LoginResult body; decoded fields are not proof of a game session."""
from dataclasses import dataclass, field
import struct

SOURCE_SHA256 = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'


def _text(text):
    if type(text) is not str or any(c in text for c in ('\0','\ufffe','\uffff')):
        raise ValueError('Unsupported LoginResult text')
    try:
        data = text.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise ValueError('LoginResult text must contain Unicode scalar values') from exc
    if len(data)>65535:
        raise ValueError('LoginResult string exceeds uint16 UTF-8 length')


def _numbers(values, count, maximum):
    if type(values) is not tuple or len(values)!=count or any(type(v) is not int or not 0<=v<=maximum for v in values):
        raise ValueError('Expected immutable unsigned LoginResult fields')


@dataclass(frozen=True, slots=True)
class LoginResultBody:
    """Ordered fields use object offsets from HEADLESS-LOGIN-RESULT-READER.md.

    u64 contains raw bits from both direct fields and nested time objects.
    No units, identifier names, timestamp conversion or defaults are inferred.
    """
    strings: tuple[str, ...] = field(repr=False)
    u32: tuple[int, ...] = field(repr=False)
    u16: tuple[int, ...] = field(repr=False)
    u64: tuple[int, ...] = field(repr=False)
    flags: tuple[bool, ...] = field(repr=False)

    def __post_init__(self):
        if type(self.strings) is not tuple or len(self.strings)!=7:
            raise ValueError('Expected seven immutable LoginResult strings')
        for text in self.strings: _text(text)
        _numbers(self.u32,3,0xffffffff)
        _numbers(self.u16,2,65535)
        _numbers(self.u64,8,0xffffffffffffffff)
        if type(self.flags) is not tuple or len(self.flags)!=5 or any(type(v) is not bool for v in self.flags):
            raise ValueError('Expected five immutable normalized LoginResult flags')

    @property
    def result_code(self):
        """Raw handler result code; zero alone does not establish a session."""
        return self.u32[0]


def decode_login_result(body, *, max_payload_size):
    """Decode exactly one response body using an explicit local byte budget."""
    if type(max_payload_size) is not int or not 99<=max_payload_size<=0xffffff:
        raise ValueError('LoginResult payload budget must be 99..16777215 bytes')
    if type(body) is not bytes:
        raise ValueError('LoginResult input must be immutable bytes')
    if len(body)>max_payload_size:
        raise BufferError('LoginResult exceeds local byte budget')
    if len(body)<99:
        raise ValueError('Truncated LoginResult body')
    position = 0

    def take(size):
        nonlocal position
        end = position+size
        if end>len(body):
            raise ValueError('Truncated LoginResult field')
        value = body[position:end]
        position = end
        return value

    def number(fmt):
        return struct.unpack(fmt,take(struct.calcsize(fmt)))[0]

    strings,u32,u16,u64,flags = [],[],[],[],[]
    # Wire sequence, independent of native object layout/padding and vptrs.
    order = 'issshqhqsqbsbqssbqqqqbiib'
    for kind in order:
        if kind=='s':
            size = number('<H')
            try: value = take(size).decode('utf-8')
            except UnicodeDecodeError as exc: raise ValueError('Invalid LoginResult UTF-8') from exc
            _text(value)
            strings.append(value)
        elif kind=='i': u32.append(number('<I'))
        elif kind=='h': u16.append(number('<H'))
        elif kind=='q': u64.append(number('<Q'))
        else: flags.append(bool(number('<B')))
    if position!=len(body):
        raise ValueError('Trailing bytes after LoginResult body')
    return LoginResultBody(tuple(strings),tuple(u32),tuple(u16),tuple(u64),tuple(flags))
