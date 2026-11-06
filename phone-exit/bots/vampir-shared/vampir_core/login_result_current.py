"""Current LoginResult extension, keeping the established prefix intact."""
from dataclasses import dataclass, field
import struct

from .login_result import LoginResultBody, decode_login_result, _text, _numbers

SOURCE_SHA256 = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
PREFIX_ORDER = 'issshqhqsqbsbqssbqqqqbiib'


@dataclass(frozen=True, slots=True)
class CurrentLoginResultBody:
    base: LoginResultBody = field(repr=False)
    raw_140: str = field(repr=False)
    raw_150: int = field(repr=False)
    raw_154: int = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.base, LoginResultBody):
            raise TypeError('Expected the established LoginResult prefix')
        _text(self.raw_140)
        _numbers((self.raw_150, self.raw_154), 2, 0xffffffff)

    @property
    def result_code(self):
        return self.base.result_code


def decode_current_login_result(body, *, max_payload_size, source_sha256):
    if source_sha256 != SOURCE_SHA256:
        raise ValueError('Current LoginResult source is not verified')
    if type(max_payload_size) is not int or not 109 <= max_payload_size <= 0xffffff:
        raise ValueError('Current LoginResult requires a bounded payload budget')
    if type(body) is not bytes or len(body) < 109:
        raise ValueError('Truncated current LoginResult')
    if len(body) > max_payload_size:
        raise BufferError('Current LoginResult exceeds payload budget')
    position = 0
    for kind in PREFIX_ORDER:
        if kind == 's':
            if position + 2 > len(body):
                raise ValueError('Truncated current LoginResult prefix')
            size = 2 + struct.unpack_from('<H', body, position)[0]
        else:
            size = {'i': 4, 'h': 2, 'q': 8, 'b': 1}[kind]
        position += size
        if position > len(body):
            raise ValueError('Truncated current LoginResult prefix')
    base = decode_login_result(body[:position], max_payload_size=max_payload_size)
    if position + 10 > len(body):
        raise ValueError('Truncated current LoginResult extension')
    length = struct.unpack_from('<H', body, position)[0]
    end = position + 2 + length
    if end + 8 != len(body):
        raise ValueError('Current LoginResult extension length differs')
    try:
        text = body[position + 2:end].decode('utf-8')
    except UnicodeError:
        raise ValueError('Invalid current LoginResult UTF-8') from None
    left, right = struct.unpack_from('<II', body, end)
    return CurrentLoginResultBody(base, text, left, right)
