"""Bounded offline HTTP response head probe, without body framing or IO.

Native delimiter/status evidence: HEADLESS-CDN-RESPONSE-HEAD.md. The strict
HTTP/1.x syntax, field parsing and budgets below are local policy, not a
translation of the client's permissive scanner. Fixed-length responses use a
strict local subset. Chunked, decompression and JSON decoding remain unresolved.
"""
from dataclasses import dataclass, field
import re

MAX_HEAD_BYTES = 16384
MAX_FIELDS = 64
MAX_BODY_BYTES = 2 * 1024 * 1024
_STATUS = re.compile(r'HTTP/(1\.[01]) ([1-5][0-9]{2})(?: [\x20-\x7e]*)?')
_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


@dataclass(frozen=True, slots=True)
class CdnResponseHead:
    version: str
    status: int
    header_bytes: int
    headers: tuple[tuple[str, str], ...] = field(repr=False)

    def get_all(self, name: str) -> tuple[str, ...]:
        """Return values in wire order, preserving duplicate fields."""
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError('Invalid response field name')
        key = name.lower()
        return tuple(value for field_name, value in self.headers if field_name == key)


def probe_cdn_response_head(data: bytes) -> CdnResponseHead | None:
    """Return a complete head or None for an incomplete bounded prefix.

    Feed accumulated bytes, not successive independent chunks. Bodies are not
    copied or validated, including NUL bytes after the head. A result does not
    mean the body is complete or that the response is suitable for CDN config.
    Invalid syntax and exhausted head budgets raise ValueError.
    """
    if not isinstance(data, bytes):
        raise ValueError('Response must be bytes')
    end = data.find(b'\r\n\r\n', 0, MAX_HEAD_BYTES)
    if end < 0:
        prefix = data[:MAX_HEAD_BYTES]
        if any(byte != 9 and byte != 10 and byte != 13 and not 32 <= byte <= 126 for byte in prefix):
            raise ValueError('Invalid response head bytes')
        if len(data) >= MAX_HEAD_BYTES:
            raise ValueError('Response head exceeds local budget')
        return None
    header_bytes = end + 4
    try:
        lines = data[:end].decode('ascii').split('\r\n')
    except UnicodeDecodeError:
        raise ValueError('Invalid response head encoding') from None
    status = _STATUS.fullmatch(lines[0])
    if not status:
        raise ValueError('Invalid response status line')
    if len(lines) - 1 > MAX_FIELDS:
        raise ValueError('Too many response fields')
    fields = []
    for line in lines[1:]:
        name, separator, value = line.partition(':')
        if not separator or not _NAME.fullmatch(name):
            raise ValueError('Invalid response field name')
        if any(char != '\t' and not 32 <= ord(char) <= 126 for char in value):
            raise ValueError('Invalid response field value')
        fields.append((name.lower(), value.strip(' \t')))
    return CdnResponseHead(status[1], int(status[2]), header_bytes, tuple(fields))


@dataclass(frozen=True, slots=True)
class CdnLengthResponse:
    head: CdnResponseHead
    body: bytes = field(repr=False)
    consumed: int


def take_cdn_length_response(data: bytes) -> CdnLengthResponse | None:
    """Take a complete, uncompressed status-200 fixed-length response.

    Native length lookup/conversion/receive comparison evidence is recorded in
    HEADLESS-CDN-RESPONSE-LENGTH.md. This profile requires exactly one decimal
    Content-Length, rejects Transfer-Encoding and Content-Range, and permits
    only absent/identity Content-Encoding. Those stricter rules and the 2 MiB
    budget are local policy. Redirects, EOF framing, partial/ranged responses,
    chunked and compression need further implementation, not silent fallback.

    Feed accumulated bytes. None means incomplete; ValueError means invalid or
    unsupported. Trailing bytes are left to the caller using consumed. The body
    is raw bytes, without text/JSON decoding or config acceptance.
    """
    head = probe_cdn_response_head(data)
    if head is None:
        return None
    if head.status != 200:
        raise ValueError('Unsupported CDN response status')
    if head.get_all('Transfer-Encoding') or head.get_all('Content-Range'):
        raise ValueError('Unsupported CDN response framing')
    encodings = head.get_all('Content-Encoding')
    if encodings and (len(encodings) != 1 or encodings[0].lower() != 'identity'):
        raise ValueError('Unsupported CDN response encoding')
    lengths = head.get_all('Content-Length')
    if len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,10}', lengths[0]):
        raise ValueError('Invalid or missing CDN content length')
    length = int(lengths[0])
    if length > MAX_BODY_BYTES:
        raise ValueError('CDN response body exceeds local budget')
    consumed = head.header_bytes + length
    if len(data) < consumed:
        return None
    return CdnLengthResponse(head, data[head.header_bytes:consumed], consumed)
